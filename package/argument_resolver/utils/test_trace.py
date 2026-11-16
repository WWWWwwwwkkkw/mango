"""
跨函数操作数追溯工具 - 基于VEX IR的静态分析

本模块使用Angr的RDA (Reaching Definitions Analysis) 在VEX IR层面进行分析：
- VEX是Angr使用的中间表示（IR），将机器码转换为统一格式
- 所有分析都在VEX语句（statements）、VEX原子（atoms）、VEX跳转（jumpkind）上进行
- 主要数据流分析对象：
  * Register: VEX寄存器（如rax、rdi等）
  * Const: VEX常量
  * Tmp: VEX临时变量
  * Mem: VEX内存访问
  
关键概念：
- ExternalCodeLocation (location='0x0'): 表示来自调用者的函数参数，非用户输入
- function_calls: RDA记录的VEX中的函数调用信息
- Ijk_Call/Ijk_Ret: VEX跳转类型，表示函数调用/返回
"""

from typing import Any


import angr
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from angr.knowledge_plugins.key_definitions.atoms import Register, Tmp, Atom
from angr.analyses.analysis import AnalysisFactory
from angr.code_location import ExternalCodeLocation
import networkx as nx

from argument_resolver.utils.rda import CustomRDA
from argument_resolver.utils.transitive_closure import (transitive_closures_from_defs, get_constant_data)
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.call_trace import traces_to_sink
from argument_resolver.utils.call_trace_visitor import CallTraceSubject
from angr.analyses.reaching_definitions.call_trace import CallTrace
from argument_resolver.handlers.base import HandlerBase
from argument_resolver.handlers import (
    handler_factory,
    StdioHandlers,
    StdlibHandlers,
    StringHandlers,
    UnistdHandlers,
)
from argument_resolver.external_function import is_an_external_input_function
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag, ParameterTag

from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation


def build_operand_atoms(insn, project):
    operand_atoms = []
    arch = project.arch

    for operand in getattr(insn, "operands", []):
        if getattr(operand, "type", None) == 1:  # 只有寄存器操作数需要
            reg_name = insn.reg_name(operand.reg)
            if reg_name in arch.registers:
                reg_offset, reg_size = arch.registers[reg_name]
                operand_atoms.append(Register(reg_offset, reg_size))
        # 内存型操作数暂不支持，直接跳过
    return operand_atoms


def collect_sink_atoms(insn, project, state=None):
    atoms = build_operand_atoms(insn, project)
    if state is not None:
        for atom in list(atoms):
            defs = state.get_definitions(atom)
            for d in defs:
                if isinstance(d.atom, MemoryLocation):
                    atoms.append(d.atom)
    unique, seen = [], set()
    for atom in atoms:
        key = (type(atom), getattr(atom, "reg_offset", None), getattr(atom, "addr", None))
        if key not in seen:
            seen.add(key)
            unique.append(atom)
    return unique


def summarize_sources(handler, closure_graph, rda):
    """
    Summarize source information from handler metadata (env_access, fd_tracker, etc.).
    
    This helps distinguish user input vs constants vs function parameters.
    
    :param handler: Handler instance used during RDA
    :param closure_graph: Dependency graph closure
    :param rda: RDA analysis object
    :return: Dictionary with source summaries
    """
    summary = {
        'user_input': False,
        'constants': [],
        'function_parameters': [],
        'external_calls': []
    }
    
    try:
        # Check handler metadata for environment access
        if hasattr(handler, 'env_access') and handler.env_access:
            summary['user_input'] = True
        
        # Check for file descriptors (could indicate user input)
        if hasattr(handler, 'fd_tracker') and handler.fd_tracker:
            summary['user_input'] = True
        
        # Extract constants from closure
        for node in closure_graph.nodes():
            atom_str = str(node.atom)
            if '<Const' in atom_str:
                try:
                    const_val_str = atom_str.split('<Const ')[1].split('>')[0]
                    const_val = int(const_val_str, 16) if const_val_str.startswith('0x') else int(const_val_str)
                    if const_val <= 0xFFFFFFFFFFFF0000:  # Filter stack offsets
                        summary['constants'].append({
                            'value': const_val,
                            'location': hex(node.codeloc.ins_addr or node.codeloc.block_addr)
                        })
                except:
                    pass
        
        # Check for external function calls
        if hasattr(rda, 'function_calls'):
            for call_loc, call_data in rda.function_calls.items():
                if hasattr(call_data, 'callee_func_addr'):
                    func = rda.project.kb.functions.get(call_data.callee_func_addr)
                    if func and func.is_external:
                        summary['external_calls'].append({
                            'name': func.name,
                            'location': hex(call_loc.ins_addr) if call_loc.ins_addr else None
                        })
    
    except Exception as e:
        print(f"[DEBUG] summarize_sources failed: {e}")
    
    return summary


def trace_external_sources(project, handler, defn, RDA, HandlerCls, depth=0, max_depth=10, visited=None):
    """
    递归追溯外部源（ExternalCodeLocation），直到找到常量或外部输入函数。
    
    参考原版 Mango 的 search_for_external_input 逻辑。
    
    :param project: Angr project
    :param handler: 当前的 handler（包含 call_trace 和 analyzed_list）
    :param defn: 需要追溯的 Definition（通常是 ExternalCodeLocation）
    :param RDA: CustomRDA AnalysisFactory
    :param HandlerCls: Handler class for creating new handlers
    :param depth: 当前递归深度
    :param max_depth: 最大递归深度
    :param visited: 已访问的 Definition 集合（防止循环）
    :return: List of traced source info dicts
    """
    if visited is None:
        visited = set()
    
    # 防止重复访问和递归过深
    defn_key = (defn.atom, defn.codeloc.ins_addr if hasattr(defn.codeloc, 'ins_addr') else 0)
    if defn_key in visited or depth >= max_depth:
        return []
    
    visited.add(defn_key)
    traced_sources = []
    
    # 检查是否是常量
    atom_str = str(defn.atom)
    if '<Const' in atom_str:
        try:
            const_val_str = atom_str.split('<Const ')[1].split('>')[0]
            const_val = int(const_val_str)
            
            if const_val <= 0xFFFFFFFFFFFF0000:  # 不是地址偏移
                return [{
                    'type': 'constant',
                    'value': const_val,
                    'atom': str(defn.atom),
                    'location': hex(defn.codeloc.ins_addr or defn.codeloc.block_addr),
                    'depth': depth
                }]
        except:
            pass
    
    # 检查是否不是 ExternalCodeLocation
    if not isinstance(defn.codeloc, ExternalCodeLocation):
        # 不是外部参数，可能是内部定义
        return [{
            'type': 'internal',
            'atom': str(defn.atom),
            'location': hex(defn.codeloc.ins_addr or defn.codeloc.block_addr),
            'depth': depth
        }]
    
    # 是 ExternalCodeLocation，需要向上追溯
    # 检查是否有 ParameterTag 或 ReturnValueTag
    has_param_tag = any(isinstance(tag, (ParameterTag, ReturnValueTag)) for tag in defn.tags)
    
    if not has_param_tag:
        # 没有参数标签，可能不是函数参数
        return []
    
    # 跳过栈指针
    if isinstance(defn.atom, Register) and defn.atom.reg_offset == handler._project.arch.sp_offset:
        return []
    
    # 从 tags 中获取函数地址
    func_addrs = {tag.function for tag in defn.tags if hasattr(tag, 'function')}
    
    if not func_addrs:
        return []
    
    # 在 handler.call_trace 中查找对应的父函数（跳过库函数）
    print(f"{'  ' * depth}  查找父函数 (func_addrs={[hex(a) for a in func_addrs]})...")
    
    for parent_idx in range(len(handler.call_trace) - 1, -1, -1):
        candidate = handler.call_trace[parent_idx]
        
        if candidate.function is None:
            continue
        
        # 跳过库函数
        if candidate.function.is_plt or candidate.function.is_simprocedure:
            print(f"{'  ' * depth}    ✗ 跳过库函数: {candidate.function.name}")
            continue
        
        # 检查是否在 func_addrs 中
        if candidate.function.addr not in func_addrs:
            continue
        
        # 找到父函数
        parent_func = candidate
        print(f"{'  ' * depth}    ✓ 找到父函数: {parent_func.function.name} @ {hex(parent_func.function.addr)}")
        
        # 检查是否是外部输入函数
        if is_an_external_input_function(parent_func.function.name):
            print(f"{'  ' * depth}    ✓✓ 找到外部输入函数: {parent_func.function.name}")
            return [{
                'type': 'external_input',
                'function': parent_func.function.name,
                'atom': str(defn.atom),
                'location': hex(parent_func.code_loc.ins_addr or parent_func.function.addr),
                'depth': depth
            }]
        
        # 需要继续向上追溯父函数的定义
        # 获取父函数的所有相关定义
        print(f"{'  ' * depth}    → 分析父函数 {parent_func.function.name} 的定义...")
        all_defns = set()
        
        # 确保 closures 已保存
        if hasattr(parent_func, 'save_closures'):
            parent_func.save_closures()
        
        # 从 closures 获取
        if hasattr(parent_func, 'closures') and parent_func.closures:
            for defn_set in parent_func.closures.values():
                all_defns.update(defn_set)
            print(f"{'  ' * depth}      从 closures 获取 {len(all_defns)} 个定义")
        
        # 从 definitions 获取
        if hasattr(parent_func, 'definitions'):
            all_defns.update(parent_func.definitions)
            print(f"{'  ' * depth}      从 definitions 获取，总计 {len(all_defns)} 个定义")
        
        # 从 return_definitions 获取
        if hasattr(parent_func, 'return_definitions'):
            all_defns.update(parent_func.return_definitions)
            print(f"{'  ' * depth}      从 return_definitions 获取，总计 {len(all_defns)} 个定义")
        
        # 递归处理父函数的每个定义
        param_defns = 0
        for parent_defn in all_defns:
            # 检查是否有参数或返回值标签
            if not any(isinstance(tag, (ParameterTag, ReturnValueTag)) for tag in parent_defn.tags):
                continue
            
            param_defns += 1
            print(f"{'  ' * depth}      → 递归追溯定义 #{param_defns}: {parent_defn.atom}")
            
            # 递归追溯
            recursive_sources = trace_external_sources(
                project, handler, parent_defn, RDA, HandlerCls,
                depth=depth + 1, max_depth=max_depth, visited=visited
            )
            
            if recursive_sources:
                print(f"{'  ' * depth}      ✓ 找到 {len(recursive_sources)} 个源")
            
            traced_sources.extend(recursive_sources)
        
        # 找到一个父函数后就停止（不继续查找其他父函数）
        break
    
    return traced_sources


def trace_operands_from_address(binary_path, sink_address, max_depth=7, 
                                  cross_function=False):
    """
    从指定地址的算术指令溯源操作数，生成定义链（基于VEX IR分析）
    
    分析流程：
    1. 将二进制代码转换为VEX IR（Angr的中间表示）
    2. 在VEX IR上运行RDA（到达定义分析）
    3. 分析VEX原子（Register/Const/Tmp/Mem）的数据流
    4. 对于函数参数（ExternalCodeLocation），递归追溯到调用者
    5. 对于函数返回值，递归进入被调用函数分析
    
    :param binary_path: 二进制文件路径
    :param sink_address: 算术指令地址（会被转换为VEX IR进行分析）
    :param max_depth: 跨函数追踪的最大深度
    :param cross_function: 是否跨函数追踪（向上追溯调用者，向下追溯被调用函数）
    :return: 操作数定义链（包含VEX层面的数据流信息）
    """
    
    print(f"[*] 加载二进制: {binary_path}")
    print(f"[*] 目标地址: {hex(sink_address)}")
    
    # ========== 步骤1: 初始化项目 ==========
    project = angr.Project(binary_path, auto_load_libs=False)
    
    # 生成CFG
    print("[*] 生成CFG...")
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True
    )
    
    # 运行VRA（变量恢复）
    print("[*] 运行VRA...")
    project.analyses.CompleteCallingConventions(
        recover_variables=True,
        analyze_callsites=True
    )
    
    # ========== 步骤2: 找到地址所在的函数（自动获取，无需手动输入）==========
    sink_function = project.kb.functions.floor_func(sink_address)
    
    if not sink_function:
        print(f"[!] 地址 {hex(sink_address)} 不属于任何已识别的函数")
        return None
    
    print(f"[+] 找到函数: {sink_function.name} @ {hex(sink_function.addr)}")
    

    # ========== 步骤3: 运行RDA分析 ==========
    print("[*] 运行RDA分析...")
    
    # 初始化变量
    trace = None
    handler = None
    start_function = None
    dep_graph = DepGraph()
    if cross_function:
        # ========== 跨函数分析：使用CustomRDA（遵循原版Mango做法）==========
        print(f"[*] 启用跨函数分析 (max_depth={max_depth})...")
        
        # 步骤3.1: 构建排除函数列表（阻止追溯到main之前）
        excluded_functions = set()
        
        # 如果存在main函数，排除所有启动函数
        if 'main' in project.kb.functions:
            main_func = project.kb.functions['main']
            
            # 常见的启动函数名称
            startup_function_names = [
                '_start', '__start', 'start',
                '__libc_start_main', '__libc_start_call_main',
                '__libc_csu_init', '__libc_csu_fini',
                '_init', '_fini',
                'frame_dummy', '__do_global_dtors_aux',
                'register_tm_clones', 'deregister_tm_clones',
                '__x86.get_pc_thunk.bx'
            ]
            
            # 收集所有启动函数
            for func_name in startup_function_names:
                if func_name in project.kb.functions:
                    func = project.kb.functions[func_name]
                    excluded_functions.add((func.addr, None))
            
            # 同时，找到所有调用main的函数（通常是启动函数）
            main_callers = list(project.kb.functions.callgraph.predecessors(main_func.addr))
            for caller_addr in main_callers:
                excluded_functions.add((caller_addr, None))
            
            if excluded_functions:
                print(f"[*] 排除 {len(excluded_functions)} 个启动函数，以main为入口点")
                for addr, _ in list(excluded_functions)[:5]:
                    func = project.kb.functions[addr]
                    print(f"    - {func.name} @ {hex(addr)}")
                if len(excluded_functions) > 5:
                    print(f"    ... 还有 {len(excluded_functions) - 5} 个")
        
        # 步骤3.2: 获取所有到达sink的调用链（使用traces_to_sink，不手动展开call graph）
        print("[*] 生成调用链...")
        traces = traces_to_sink(
            sink=sink_function,
            callgraph=project.kb.functions.callgraph,
            max_depth=max_depth,
            excluded_functions=excluded_functions
        )
        
        if not traces:
            print(f"[!] 未找到到达函数 {sink_function.name} 的调用链")
            print("[*] 回退到单函数分析...")
            cross_function = False
        else:
            print(f"[+] 找到 {len(traces)} 条调用链")
            
            # 选择第一条trace
            trace = list(traces)[0]
            
            # ========== 过滤掉库函数的 callsite ==========
            # 剔除 callee 是 is_plt 或 is_simprocedure 的 callsite
            # 这样 handler.call_trace 里只剩业务函数
            print("[*] 过滤库函数 callsites...")
            original_count = len(trace.callsites)
            filtered = []
            for cs in trace.callsites:
                caller = project.kb.functions.get(cs.caller_func_addr)
                callee = project.kb.functions.get(cs.callee_func_addr)
                
                caller_name = caller.name if caller else hex(cs.caller_func_addr)
                callee_name = callee.name if callee else hex(cs.callee_func_addr)
                
                if callee is None:
                    print(f"  警告: callee 为 None: {caller_name} -> {hex(cs.callee_func_addr)}")
                    continue
                
                # 检查 callee 是否是库函数
                if callee.is_plt or callee.is_simprocedure:
                    print(f"  ✗ 过滤库函数: {caller_name} -> {callee_name} (is_plt={callee.is_plt}, is_simprocedure={callee.is_simprocedure})")
                    continue
                
                # 保留业务函数
                print(f"  ✓ 保留: {caller_name} -> {callee_name}")
                filtered.append(cs)
            
            trace.callsites = filtered
            print(f"  过滤前: {original_count} 个 callsites")
            print(f"  过滤后: {len(trace.callsites)} 个 callsites (业务函数)")
            
            print("[DEBUG] CallTrace callsites (过滤后):")
            for cs in trace.callsites:
                print(f"  caller={hex(cs.caller_func_addr)} callee={hex(cs.callee_func_addr)}")
            # 打印调用链（仅用于调试）
            if trace.callsites:
                print(f"[*] 使用调用链:")
                for callsite in reversed(trace.callsites):
                    caller_func = project.kb.functions[callsite.caller_func_addr]
                    callee_func = project.kb.functions[callsite.callee_func_addr]
                    print(f"    {caller_func.name} ({hex(callsite.caller_func_addr)}) -> {callee_func.name} ({hex(callsite.callee_func_addr)})")
                print(f"    -> {sink_function.name} (sink)")
            else:
                print(f"[*] 调用链: {sink_function.name} (起点即为sink)")
            
            # 步骤3.3: 创建CallTraceSubject（让CustomRDA + LocalHandler自己沿着trace走）
            function_address = trace.current_function_address()
            start_function = project.kb.functions[function_address]
            subject = CallTraceSubject(trace, start_function)
            
            print(f"[*] 分析起点: {start_function.name} @ {hex(function_address)}")
            
            # ========================================================================
            # 遵循原版Mango做法：只设置sink observation point，其余由LocalHandler管理
            # ========================================================================
            
            # Step 1: Build sink_atoms (arithmetic operands + function parameters)
            print(f"[*] 构建 sink_atoms (算术操作数 + 函数参数)...")
            
            # 1.1: Extract function parameter atoms
            sink_atoms = []
            seen_atoms = set()
            try:
                param_atoms = Utils.get_atoms_from_function(sink_function, project.arch)
                for atom in param_atoms:
                    key = (type(atom), getattr(atom, "reg_offset", None), getattr(atom, "size", None))
                    if key not in seen_atoms:
                        seen_atoms.add(key)
                        sink_atoms.append(atom)
                if param_atoms:
                    print(f"  ✓ 函数参数: {len(param_atoms)} 个")
            except Exception as e:
                print(f"  [!] 提取函数参数失败: {e}")
            
            # 1.2: Extract arithmetic operands from the instruction
            block = project.factory.block(sink_address)
            ins_idx = block.instruction_addrs.index(sink_address)
            insn = block.capstone.insns[ins_idx]

            operand_atoms = build_operand_atoms(insn, project)
            added = 0
            for atom in operand_atoms:
                key = (type(atom), getattr(atom, "reg_offset", None), getattr(atom, "size", None))
                if key not in seen_atoms:
                    seen_atoms.add(key)
                    sink_atoms.append(atom)
                    added += 1
            if added:
                print(f"  ✓ 算术操作数: {added} 个")

            
            if not sink_atoms:
                print(f"  [!] 未找到任何 sink_atoms，使用 VEX Use-Def 分析...")
                # Fallback: VEX-based parameter detection
                try:
                    entry_block = project.factory.block(sink_function.addr)
                    vex = entry_block.vex
                    used_regs_offsets = set()
                    defined_regs_offsets = set()
                    ignored_offsets = {project.arch.sp_offset, project.arch.ip_offset}
                    if hasattr(project.arch, 'bp_offset') and project.arch.bp_offset:
                        ignored_offsets.add(project.arch.bp_offset)
                    
                    def scan_expression_for_gets(expr):
                        if expr.tag == 'Iex_Get':
                            if expr.offset not in defined_regs_offsets:
                                used_regs_offsets.add(expr.offset)
                        elif hasattr(expr, 'args'):
                            for arg in expr.args:
                                scan_expression_for_gets(arg)
                    
                    for stmt in vex.statements:
                        if stmt.tag == 'Ist_WrTmp':
                            scan_expression_for_gets(stmt.data)
                        elif stmt.tag == 'Ist_Store':
                            scan_expression_for_gets(stmt.addr)
                            scan_expression_for_gets(stmt.data)
                        elif stmt.tag == 'Ist_Put':
                            scan_expression_for_gets(stmt.data)
                            defined_regs_offsets.add(stmt.offset)
                        elif stmt.tag == 'Ist_Exit':
                            scan_expression_for_gets(stmt.guard)
                    
                    for offset in used_regs_offsets:
                        if offset not in ignored_offsets:
                            sink_atoms.append(Register(offset, project.arch.bytes))
                    
                    if sink_atoms:
                        print(f"  ✓ VEX 分析识别: {len(sink_atoms)} 个")
                except Exception as e:
                    print(f"  [!] VEX 分析失败: {e}")
            
            print(f"[*] 总计 sink_atoms: {len(sink_atoms)} 个")
            print(f"[DEBUG] sink_atoms 内容:")
            for atom in sink_atoms:
                print(f"  - {atom}")

            # Step 2: Create handler using handler_factory（保持LocalHandler的默认逻辑）
            print(f"[*] 创建 Handler (使用 handler_factory)...")
            HandlerCls = handler_factory([
                StdioHandlers,
                StdlibHandlers,
                StringHandlers,
                UnistdHandlers,
            ])
            
            handler = HandlerCls(
                project=project,
                sink_function=sink_function,
                sink_atoms=sink_atoms,
                assumed_execution=False,
                taint_trace=False,
                forward_trace=False,
            )
            print(f"  ✓ Handler 类型: {HandlerCls.__name__}")
            
            # Step 3: observation_points 只保留 sink 指令（其余由LocalHandler自己管理）
            # 原版Mango做法：只把sink指令加入observation set，其余的点都由
            # self._rda._observation_points（内部默认）和LocalHandler控制
            observation_points = {('insn', sink_address, OP_BEFORE)}
            print(f"[*] 观察点: 仅保留 sink 指令 {hex(sink_address)} (其余由LocalHandler管理)")
            
            # Step 4: Run CustomRDA with AnalysisFactory（遵循原版Mango的参数配置）
            print(f"\n[*] 运行 CustomRDA 分析...")
            print(f"  • Subject: CallTraceSubject (起点: {start_function.name})")
            print(f"  • Handler: {HandlerCls.__name__}")
            print(f"  • Sink atoms: {len(sink_atoms)}")
            print(f"  • Observation points: {len(observation_points)} (仅sink)")
            
            RDA = AnalysisFactory(project, CustomRDA)
            
            # max_iter 仿照Mango的默认值（base.py中使用2，但这里可能需要更多以支持跨函数分析）
            max_iter = max(20, len(trace.callsites) * 5)
            
            rda = RDA(
                subject=subject,
                function_handler=handler,
                observation_points=set(observation_points),
                kb=project.kb,
                dep_graph=dep_graph,
                max_iterations=max_iter,
            )
            
            print(f"  ✓ RDA 分析完成")
            
            # ========== 清理 handler 中的库函数 ==========
            # 在 RDA 运行完成后，再次过滤 handler.call_trace、white_list、analyzed_list
            # 确保这些列表中只包含业务函数
            print(f"\n[*] 清理 handler 中的库函数...")
            
            # 清理 call_trace
            if hasattr(handler, 'call_trace') and handler.call_trace:
                original_trace = list(handler.call_trace)
                handler.call_trace = [
                    sf for sf in handler.call_trace 
                    if sf.function and not sf.function.is_plt and not sf.function.is_simprocedure
                ]
                removed = len(original_trace) - len(handler.call_trace)
                if removed > 0:
                    print(f"  从 call_trace 移除 {removed} 个库函数")
                    for sf in original_trace:
                        if sf not in handler.call_trace:
                            print(f"    ✗ 移除: {sf.function.name if sf.function else 'Unknown'}")
            
            # 清理 white_list
            if hasattr(handler, 'white_list') and handler.white_list:
                original_wl = list(handler.white_list)
                handler.white_list = [
                    sf for sf in handler.white_list 
                    if sf.function and not sf.function.is_plt and not sf.function.is_simprocedure
                ]
                removed = len(original_wl) - len(handler.white_list)
                if removed > 0:
                    print(f"  从 white_list 移除 {removed} 个库函数")
            
            # 清理 analyzed_list
            if hasattr(handler, 'analyzed_list') and handler.analyzed_list:
                original_al = list(handler.analyzed_list)
                handler.analyzed_list = [
                    sf for sf in handler.analyzed_list 
                    if sf.function and not sf.function.is_plt and not sf.function.is_simprocedure
                ]
                removed = len(original_al) - len(handler.analyzed_list)
                if removed > 0:
                    print(f"  从 analyzed_list 移除 {removed} 个库函数")
            
            # Step 5: Extract results from observed_results
            print(f"\n[*] 提取分析结果...")
            
            print(f"[+] CustomRDA 分析完成")
            print(f"  观察到的结果数: {len(rda.observed_results)}")
            
            # Check handler's call_trace for debugging
            if hasattr(handler, 'call_trace'):
                print(f"\n[DEBUG] Handler call_trace (清理后):")
                print(f"  长度: {len(handler.call_trace)}")
                if handler.call_trace:
                    for i, stored_func in enumerate(handler.call_trace[:15], 1):
                        func_name = stored_func.function.name if stored_func.function else "Unknown"
                        is_lib = stored_func.function.is_plt or stored_func.function.is_simprocedure if stored_func.function else False
                        mark = "[库]" if is_lib else "[业务]"
                        print(f"    {i}. {mark} {func_name}")
                else:
                    print(f"  ⚠️ call_trace为空")
 
    if not cross_function:
        # ========== 单函数分析：使用angr原生RDA ==========
        print("[*] 使用单函数分析模式...")
        observation_points = {('insn', sink_address, OP_BEFORE)}
        rda = project.analyses.ReachingDefinitions(
            subject=sink_function,
            observation_points=set(observation_points),
            dep_graph=DepGraph(),
            max_iterations=2
        )
        
        print(f"[+] RDA分析完成")
    
    # ========================================================================
    # Step 6: Extract results from RDA observed_results
    # ========================================================================

    if handler is not None:
        print(f"[DEBUG] handler.white_list: {[f.name for f in handler.white_list]}")
        print(f"[DEBUG] handler.analyzed_list: {[f.name for f in handler.analyzed_list]}")

        if handler.call_trace:
            sink_func = handler.call_trace[-1]
            print("[DEBUG] sink constant_data:")
            for atom, vals in sink_func.constant_data.items():
                print(f"  {atom} -> {vals}")
        print(f"[DEBUG] current sink_atoms: {[str(a) for a in handler._sink_atoms]}")
    # Get state at sink address
    state = rda.observed_results.get(('insn', sink_address, OP_BEFORE))
    if state and handler is not None:
        extra_atoms = collect_sink_atoms(insn, project, state)
        new_atoms = []
        seen = {(type(atom), getattr(atom, "reg_offset", None), getattr(atom, "addr", None))
                for atom in handler._sink_atoms}
        for atom in extra_atoms:
            key = (type(atom), getattr(atom, "reg_offset", None), getattr(atom, "addr", None))
            if key not in seen:
                seen.add(key)
                handler._sink_atoms.append(atom)
                new_atoms.append(atom)
        if new_atoms:
            print(f"[DEBUG] 补充 sink_atoms (state-based): {[str(a) for a in new_atoms]}")

    if not state:
        print(f"\n[!] 无法获取地址 {hex(sink_address)} 的状态")
        
        print(f"\n[DEBUG] RDA分析诊断:")
        print(f"  总观察点数: {len(rda.observed_results)}")
        
        # 检查目标函数中的观察点
        sink_observations = [k for k in rda.observed_results.keys() 
                            if k[0] == 'insn' and 
                            sink_function.addr <= k[1] < sink_function.addr + sink_function.size]
        
        if sink_observations:
            print(f"  ✓ 目标函数 {sink_function.name} 中有 {len(sink_observations)} 个观察点")
            print(f"    示例:")
            for obs in sink_observations[:5]:
                print(f"      - {obs[0]}: {hex(obs[1])} {obs[2]}")
        else:
            print(f"  ✗ 目标函数 {sink_function.name} 中没有观察点")
            print(f"    这意味着 RDA 没有进入目标函数")
        
        # 显示实际观察到的函数
        print(f"\n  RDA 实际分析的函数:")
        analyzed_funcs = set()
        for key in rda.observed_results.keys():
            if key[0] in ('insn', 'node'):
                addr = key[1]
                func = project.kb.functions.floor_func(addr)
                if func:
                    analyzed_funcs.add((func.name, hex(func.addr)))
        
        for fname, faddr in sorted(analyzed_funcs)[:10]:
            if cross_function and trace and trace.callsites:
                in_chain = "✓" if any(faddr == hex(cs.callee_func_addr) or faddr == hex(cs.caller_func_addr) 
                                       for cs in trace.callsites) else "-"
            else:
                in_chain = "?"
            print(f"    {in_chain} {fname} @ {faddr}")
        
        if len(analyzed_funcs) > 10:
            print(f"    ... 还有 {len(analyzed_funcs) - 10} 个函数")
        
        print(f"\n  前10个观察点:")
        for i, key in enumerate(list(rda.observed_results.keys())[:10], 1):
            if key[0] == 'insn':
                func = project.kb.functions.floor_func(key[1])
                func_name = func.name if func else "unknown"
                print(f"    {i}. {key[0]}: {hex(key[1])} {key[2]} (in {func_name})")
            else:
                print(f"    {i}. {key}")
        
        print(f"\n[建议]:")
        if not sink_observations:
            print(f"  → RDA 没有进入目标函数 {sink_function.name}")
            print(f"  → 可能原因:")
            print(f"     1. max_iterations 不足（尝试增加）")
            print(f"     2. 函数调用识别问题（检查 CFG）")
            print(f"     3. handler 配置问题")
            print(f"  → 尝试增加 max_iterations 或使用单函数分析模式")
        
        return None
    print(f"[+] 成功获取状态")
    # ========== 步骤5: 提取操作数（依赖angr的VEX处理）==========
    # angr已经自动处理了VEX，我们只需要查询相关的寄存器
    
    # 获取该地址的指令
    block = project.factory.block(sink_address)
    ins_idx = block.instruction_addrs.index(sink_address)
    insn = block.capstone.insns[ins_idx]
    
    print(f"[*] 指令: {insn.mnemonic} {insn.op_str}")
    
    # 提取操作数对应的寄存器（依赖capstone，angr已集成）
    operand_atoms = []
    arch = project.arch
    
    for operand in insn.operands:
        if operand.type == 1:  # 寄存器类型
            reg_name = insn.reg_name(operand.reg)
            if reg_name in arch.registers:
                reg_offset, reg_size = arch.registers[reg_name]
                atom = Register(reg_offset, reg_size)
                operand_atoms.append(atom)
                print(f"  操作数: {reg_name} -> {atom}")
    
    if not operand_atoms:
        print("[!] 未找到寄存器操作数")
        return None
    
    print(f"[+] 找到 {len(operand_atoms)} 个操作数")
    
    # ========== 步骤7: 对每个操作数生成定义链（使用mango核心函数）==========
    result = {
        'sink_address': hex(sink_address),
        'function': sink_function.name,
        'instruction': f"{insn.mnemonic} {insn.op_str}",
        'cross_function': cross_function,
        'operands': []
    }
    
    # 如果是跨函数分析，添加调用链信息
    if cross_function and trace.callsites:
        call_chain = []
        for callsite in reversed(trace.callsites):
            caller_func = project.kb.functions[callsite.caller_func_addr]
            call_chain.append({
                'function': caller_func.name,
                'address': hex(callsite.caller_func_addr)
            })
        call_chain.append({
            'function': sink_function.name,
            'address': hex(sink_function.addr)
        })
        result['call_chain'] = call_chain
        result['analysis_start'] = start_function.name
    
    for i, atom in enumerate(operand_atoms, 1):
        print(f"\n[*] 溯源操作数 #{i}: {atom}")
        
        # 获取该操作数的所有定义
        definitions = state.get_definitions(atom)
        
        if not definitions:
            print(f"  [!] 未找到定义")
            continue
        
        print(f"  [+] 找到 {len(definitions)} 个定义")
        
        # ========== 使用mango核心函数1: transitive_closures_from_defs ==========
        closures = transitive_closures_from_defs(definitions, rda.dep_graph)
        
        operand_result = {
            'atom': str(atom),
            'definition_count': len(definitions),
            'chains': []
        }
        
        # 分析每个定义的传递闭包
        for defn, closure_graph in closures.items():
            print("--------------------------------------------------------")
            print("[DEBUG] nodes:")
            for node in closure_graph.nodes():
                print(f"      {hex(node.codeloc.ins_addr or node.codeloc.block_addr)} -> {node.atom}")
            print("[DEBUG] edges:")
            for src,dst in closure_graph.edges():
                print(f"      {src.atom} -> {dst.atom}")
            print("--------------------------------------------------------")
            print(f"\n  定义: {defn}")
            print(f"    位置: {hex(defn.codeloc.ins_addr or defn.codeloc.block_addr)}")
            print(f"    闭包大小: {len(closure_graph.nodes())} 个定义")
            
            # 找到源头定义（入度为0）
            source_nodes = [n for n in closure_graph.nodes() 
                           if closure_graph.in_degree(n) == 0]
            
            # 注意：实际记录的源头数会更少，因为过滤了地址偏移
            print(f"    候选源头数: {len(source_nodes)} (过滤地址偏移后)")
            
            chain_info = {
                'root_definition': str(defn),
                'root_location': hex(defn.codeloc.ins_addr or defn.codeloc.block_addr),
                'closure_size': len(closure_graph.nodes()),
                'source_definitions': [],
                'all_definitions': [],
                'dependency_paths': []
            }
            
            def _resolve_location(codeloc):
                """
                Try to recover a more precise instruction address for a codeloc.
                If ins_addr is missing, use stmt_idx within the block to recover
                the corresponding instruction address.
                """
                ins = getattr(codeloc, "ins_addr", None)
                blk = getattr(codeloc, "block_addr", None)
                if ins is None and blk is not None and hasattr(codeloc, "stmt_idx"):
                    try:
                        block = project.factory.block(blk)
                        idx = codeloc.stmt_idx
                        if idx is not None and 0 <= idx < len(block.instruction_addrs):
                            ins = block.instruction_addrs[idx]
                    except Exception:
                        pass
                return ins if ins is not None else blk

            # 记录所有定义
            for node in closure_graph.nodes():
                node_loc = _resolve_location(node.codeloc)
                node_func = project.kb.functions.floor_func(node_loc) if node_loc else None
                chain_info['all_definitions'].append({
                    'definition': str(node),
                    'atom': str(node.atom),
                    'location': hex(node_loc) if node_loc else "?",
                    'function_name': node_func.name if node_func else "unknown"
                })
            
            # 记录源头定义
            for src_node in source_nodes:

                live_defs = state.live_definitions if hasattr(state,"live_definitions") else state
                loc = _resolve_location(src_node.codeloc)
                func = project.kb.functions.floor_func(loc) if loc else None

                src_info = {
                    'definition': str(src_node),
                    'atom': str(src_node.atom),
                    'location': hex(loc) if loc else "?",
                    'function_name': func.name if func else "unknown",
                    'is_external': isinstance(src_node.codeloc, ExternalCodeLocation)
                }

                print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                print(f"[DEBUG] check source {src_info['atom']} @ {src_info['location']}")
                mv = live_defs.get_value_from_definition(src_node)
                const_vals = get_constant_data(src_node, mv, live_defs) if mv is not None else None
                keep = bool(const_vals and any(v is not None for v in const_vals))
                if not keep and src_info["is_external"]:
                    keep = True  # 函数参数
                if not keep and isinstance(src_node.atom, Register):
                    keep = True  # 寄存器值（即使不可具体化）
                if not keep and isinstance(src_node.atom, MemoryLocation):
                    keep = True  # 栈/内存上的源

                if not keep:
                    print(f"[DEBUG] skip {src_info['atom']} (const_vals={const_vals})")
                    continue

                if const_vals and any(v is not None for v in const_vals):
                    resolved_values = []
                    for v in const_vals:
                        if v is None:
                            continue
                        if hasattr(v, "concrete_value"):
                            try:
                                resolved_values.append(int(v.concrete_value))
                                continue
                            except Exception:
                                pass
                        resolved_values.append(v)
                    if resolved_values:
                        src_info["values"] = resolved_values
                print(f"[DEBUG] keep {src_info['atom']} values={src_info.get('values')}")
                print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                
                # ========== 跨函数追溯：使用递归逻辑追溯到最终源 ==========
                # 使用新的递归函数 trace_external_sources，遵循原版 Mango 的 search_for_external_input 逻辑
                if cross_function and src_info['is_external'] and trace and handler.call_trace:
                    print(f"\n[*] 检测到来自调用者的参数 {src_info['atom']}，开始递归追溯...")
                    
                    try:
                        # 使用递归函数追溯外部源
                        traced_sources = trace_external_sources(
                            project=project,
                            handler=handler,
                            defn=src_node,
                            RDA=RDA,
                            HandlerCls=HandlerCls,
                            depth=0,
                            max_depth=10,
                            visited=None
                        )
                        
                        if traced_sources:
                            src_info['traced_sources'] = traced_sources
                            print(f"  ✓ 递归追溯完成，找到 {len(traced_sources)} 个源")
                            for ts in traced_sources:
                                print(f"    - {ts['type']}: {ts.get('atom', ts.get('function', '?'))} @ {ts.get('location', '?')} (depth={ts.get('depth', 0)})")
                        else:
                            print(f"  ⚠️ 递归追溯未找到源")
                    
                    except Exception as e:
                        print(f"  [!] 递归追溯失败: {e}")
                        import traceback
                        traceback.print_exc()
                
                # ========== 【LEGACY】单层跨函数追溯（已被递归逻辑替代）==========
                # 以下代码保留用于参考，但不再执行
                if False and cross_function and src_info['is_external'] and trace and handler.call_trace:
                    print(f"\n[*] 检测到来自调用者的参数 {src_info['atom']}，开始跨函数追溯...")
                    
                    # 确保有足够的调用栈深度（至少需要2层：当前函数 + 父函数）
                    if len(handler.call_trace) >= 2:
                        current_func = handler.call_trace[-1]
                        
                        # ========== 跳过库函数父节点，找到真正的业务函数 ==========
                        print(f"  [DEBUG] handler.call_trace 长度: {len(handler.call_trace)}")
                        for idx, sf in enumerate(handler.call_trace):
                            func = sf.function
                            if func:
                                is_lib = func.is_plt or func.is_simprocedure
                                mark = "[库]" if is_lib else "[业务]"
                                print(f"    [{idx}] {mark} {func.name} @ {hex(func.addr)}")
                        
                        parent_func = None
                        parent_idx = len(handler.call_trace) - 2
                        
                        print(f"  开始从 index {parent_idx} 向前查找业务函数...")
                        
                        while parent_idx >= 0:
                            candidate = handler.call_trace[parent_idx]
                            func = candidate.function
                            
                            if func and not func.is_plt and not func.is_simprocedure:
                                # 找到业务函数
                                parent_func = candidate
                                print(f"  ✓ 找到业务函数: {func.name} @ {hex(func.addr)} (index {parent_idx})")
                                break
                            else:
                                # 跳过库函数
                                func_name = func.name if func else "Unknown"
                                is_plt = func.is_plt if func else False
                                is_sp = func.is_simprocedure if func else False
                                print(f"  ✗ 跳过库函数 [index {parent_idx}]: {func_name} (is_plt={is_plt}, is_simprocedure={is_sp})")
                            
                            parent_idx -= 1
                        
                        if parent_func is None:
                            print(f"  ⚠️ 未找到合适的父函数（所有父节点都是库函数），跳过追溯")
                            continue
                        
                        print(f"  当前函数: {current_func.function.name} @ {hex(current_func.function.addr)}")
                        print(f"  父函数: {parent_func.function.name} @ {hex(parent_func.function.addr)}")
                        
                        # 从 src_node.atom 获取需要追溯的寄存器
                        # ExternalCodeLocation 的 atom 通常是参数寄存器（rdi, rsi等）
                        traced_atom = src_node.atom
                        
                        if isinstance(traced_atom, Register):
                            print(f"  追溯寄存器: {traced_atom}")
                            
                            try:
                                # ========== 1. 构造 CallTraceSubject ==========
                                # 关键修正：
                                # 1) 需要构造新的 CallTrace，包含从起点到父函数的调用链
                                # 2) CallTraceSubject 的第二个参数必须是 parent_func.function
                                #    （这决定了 RDA 从哪个函数开始分析）
                                
                                # 构造父函数的 CallTrace
                                # 关键：target 是父函数地址，只包含到达父函数之前的 callsites
                                parent_trace = CallTrace(parent_func.function.addr)
                                parent_trace.callsites = []
                                
                                for cs in trace.callsites:
                                    if cs.caller_func_addr == parent_func.function.addr:
                                        # 到父函数为止，不包含"父函数→子函数"这条 callsite
                                        break
                                    parent_trace.callsites.append(cs)
                                
                                # 如果父函数是起点，callsites 为空，Subject 只在父函数内部运行
                                
                                # 创建 CallTraceSubject，关键：第二个参数是 parent_func.function
                                # 而不是 start_function！
                                parent_subject = CallTraceSubject(parent_trace, parent_func.function)
                                
                                print(f"  构造 parent_trace:")
                                print(f"    target: {hex(parent_trace.target)}")
                                print(f"    callsites: {len(parent_trace.callsites)} 条")
                                if parent_trace.callsites:
                                    for cs in parent_trace.callsites:
                                        caller = project.kb.functions.get(cs.caller_func_addr)
                                        callee = project.kb.functions.get(cs.callee_func_addr)
                                        caller_name = caller.name if caller else hex(cs.caller_func_addr)
                                        callee_name = callee.name if callee else hex(cs.callee_func_addr)
                                        print(f"      {caller_name} -> {callee_name}")
                                print(f"    起始函数: {parent_func.function.name} (修正后)")
                                print(f"    预期 current_function_address: {hex(parent_trace.current_function_address() if parent_trace.callsites else parent_func.function.addr)}")
                                
                                # ========== 2. 确定追溯的 atoms ==========
                                # 使用父函数的 atoms（从 parent_func.atoms 或 parent_func.args_atoms）
                                # 这些是父函数在 callsite 上真实传递的参数
                                parent_sink_atoms = []
                                
                                # 尝试从 parent_func 的 atoms 中找到与 traced_atom 对应的 atom
                                # （考虑调用约定）
                                if hasattr(parent_func, 'atoms') and parent_func.atoms:
                                    # 优先使用 parent_func.atoms（已经通过 tag_params 处理过）
                                    parent_sink_atoms = list(parent_func.atoms)
                                    print(f"  使用父函数的 atoms (已标记): {len(parent_sink_atoms)} 个")
                                else:
                                    # 备用方案：使用 traced_atom（但可能不准确）
                                    parent_sink_atoms = [traced_atom]
                                    print(f"  备用方案：使用 traced_atom")
                                
                                print(f"  父函数分析目标: {[str(a) for a in parent_sink_atoms]}")
                                
                                # ========== 3. 创建 Handler ==========
                                ParentHandlerCls = handler_factory([
                                    StdioHandlers,
                                    StdlibHandlers,
                                    StringHandlers,
                                    UnistdHandlers,
                                ])
                                
                                parent_handler = ParentHandlerCls(
                                    project=project,
                                    sink_function=parent_func.function,
                                    sink_atoms=parent_sink_atoms,
                                    assumed_execution=True,
                                    taint_trace=False,
                                    forward_trace=False,
                                )
                                
                                # ========== 4. 设置 observation_points ==========
                                # 遵循 LocalHandler.run_rda 的做法（line 238）：
                                # observation_points = self._rda._observation_points | {("insn", x, OP_AFTER) for x in stored_func.exit_site_addresses}
                                # 
                                # 在我们的场景中：
                                # - 主要观察点：父函数调用子函数的 callsite (OP_BEFORE，捕获传递的参数)
                                # - 额外观察点：父函数的 exit_sites (OP_AFTER，用于完整的数据流分析)
                                
                                parent_observation_points = {('insn', parent_func.code_loc.ins_addr, OP_BEFORE)}
                                
                                # 添加父函数的退出点（遵循 run_rda 的做法）
                                try:
                                    exit_sites = parent_func.function.ret_sites + parent_func.function.jumpout_sites
                                    for site in exit_sites:
                                        parent_observation_points.add(('insn', site.addr, OP_AFTER))
                                    print(f"  添加 {len(exit_sites)} 个退出点到观察列表")
                                except Exception as e:
                                    print(f"  [!] 无法获取退出点: {e}")
                                
                                print(f"  运行父函数 RDA...")
                                print(f"    Subject: {parent_func.function.name}")
                                print(f"    主观察点: {hex(parent_func.code_loc.ins_addr)} (callsite, OP_BEFORE)")
                                print(f"    总观察点: {len(parent_observation_points)} 个")
                                print(f"    方式: 复用原版 Mango 的 observation 策略")
                                
                                # ========== 5. 运行 CustomRDA on 父函数 ==========
                                parent_rda = RDA(
                                    subject=parent_subject,
                                    function_handler=parent_handler,
                                    observation_points=parent_observation_points,
                                    kb=project.kb,
                                    dep_graph=DepGraph(),
                                    max_iterations=max_iter,
                                )
                                
                                # 提取父函数的结果
                                parent_state = parent_rda.observed_results.get(
                                    ('insn', parent_func.code_loc.ins_addr, OP_BEFORE)
                                )
                                
                                if parent_state:
                                    print(f"  ✓ 成功获取父函数状态")
                                    
                                    # 关键修正：对 parent_sink_atoms 中的每个 atom 都做 get_definitions
                                    # 而不是只用 traced_atom（父子函数的寄存器可能不一致）
                                    all_parent_defs = set()
                                    for parent_atom in parent_sink_atoms:
                                        parent_defs = parent_state.get_definitions(parent_atom)
                                        if parent_defs:
                                            all_parent_defs.update(parent_defs)
                                            print(f"  找到 {len(parent_defs)} 个定义 (atom: {parent_atom})")
                                    
                                    if all_parent_defs:
                                        print(f"  总计找到 {len(all_parent_defs)} 个父函数定义")
                                        
                                        # 对父函数的定义也进行闭包分析
                                        parent_closures = transitive_closures_from_defs(
                                            all_parent_defs, 
                                            parent_rda.dep_graph
                                        )
                                        
                                        # 收集父函数的源头定义
                                        traced_sources = []
                                        
                                        for parent_defn, parent_closure_graph in parent_closures.items():
                                            parent_source_nodes = [
                                                n for n in parent_closure_graph.nodes() 
                                                if parent_closure_graph.in_degree(n) == 0
                                            ]
                                            
                                            for parent_src in parent_source_nodes:
                                                parent_src_info = {
                                                    'atom': str(parent_src.atom),
                                                    'location': hex(parent_src.codeloc.ins_addr or parent_src.codeloc.block_addr),
                                                    'function': parent_func.function.name,
                                                    'is_external': isinstance(parent_src.codeloc, ExternalCodeLocation)
                                                }
                                                
                                                # 判断类型
                                                atom_str = str(parent_src.atom)
                                                if '<Const' in atom_str:
                                                    try:
                                                        const_val_str = atom_str.split('<Const ')[1].split('>')[0]
                                                        const_val = int(const_val_str)
                                                        
                                                        if const_val <= 0xFFFFFFFFFFFF0000:
                                                            parent_src_info['type'] = 'constant'
                                                            parent_src_info['value'] = const_val
                                                            parent_src_info['traced_from'] = parent_func.function.name
                                                            parent_src_info['call_location'] = hex(parent_func.code_loc.ins_addr)
                                                            parent_src_info['in_function'] = parent_func.function.name
                                                            traced_sources.append(parent_src_info)
                                                            
                                                            print(f"    ↓ 追溯到常量: {hex(const_val)} @ {parent_src_info['location']}")
                                                    except:
                                                        pass
                                                elif parent_src_info['is_external']:
                                                    # 递归的ExternalCodeLocation，可以继续往上追溯
                                                    # 但为了避免无限递归，这里只记录
                                                    parent_src_info['type'] = 'external_parameter'
                                                    traced_sources.append(parent_src_info)
                                                    print(f"    ↓ 追溯到更上层参数: {parent_src_info['atom']}")
                                                else:
                                                    # 其他类型的源（寄存器、内存等）
                                                    parent_src_info['type'] = 'register_or_memory'
                                                    traced_sources.append(parent_src_info)
                                                    print(f"    ↓ 追溯到: {parent_src_info['atom']} @ {parent_src_info['location']}")
                                        
                                        # 将追溯结果添加到当前 src_info
                                        if traced_sources:
                                            src_info['traced_sources'] = traced_sources
                                            print(f"  ✓ 跨函数追溯完成，找到 {len(traced_sources)} 个源")
                                    else:
                                        print(f"  ⚠️ 未在父函数中找到 parent_sink_atoms 的定义: {[str(a) for a in parent_sink_atoms]}")
                                else:
                                    print(f"  ⚠️ 无法获取父函数状态")
                                    
                            except Exception as e:
                                print(f"  [!] 跨函数追溯失败: {e}")
                                import traceback
                                traceback.print_exc()
                        else:
                            print(f"  ⚠️ src_node.atom 不是 Register 类型，跳过追溯")
                    else:
                        print(f"  ⚠️ 调用栈深度不足 (需要≥2，当前={len(handler.call_trace)})")
                
                # 判断是数据源还是地址偏移
                atom_str = str(src_node.atom)
                if '<Const' in atom_str:
                    try:
                        # 提取常量值
                        const_val_str = atom_str.split('<Const ')[1].split('>')[0]
                        const_val = int(const_val_str)
                        
                        # 判断是否为地址偏移（接近-1的大数，即栈偏移）
                        if const_val > 0xFFFFFFFFFFFF0000:  # 大于 2^64 - 2^16
                            src_info['type'] = 'address_offset'
                            src_info['offset'] = const_val - 2**64  # 转换为负数
                        else:
                            src_info['type'] = 'data_value'
                            src_info['value'] = const_val
                    except:
                        src_info['type'] = 'unknown'
                else:
                    src_info['type'] = 'register_or_memory'
                
                # 只保存非地址偏移的源头定义
                if src_info.get('type') != 'address_offset':
                    chain_info['source_definitions'].append(src_info)
                    
                    # 根据类型打印不同的标记
                    if src_info.get('type') == 'data_value':
                        if src_info['value'] <= 0xFFFFFFFF:
                            print(f"      [数据] {src_node.atom} ({src_info['function_name']}) @ {src_info['location']} (值: {hex(src_info['value'])})")
                        else:
                            print(f"      [数据] {src_node.atom} ({src_info['function_name']}) @ {src_info['location']} (值: {src_info['value']})")
                    else:
                        # 更准确的术语：is_external表示来自函数参数，而非用户输入
                        param_mark = " [函数参数]" if src_info['is_external'] else ""
                        print(f"      {src_node.atom} ({src_info['function_name']}) @ {src_info['location']}{param_mark}")
                    
                    # 只为数据源生成路径
                    try:
                        paths = list(nx.all_simple_paths(
                            closure_graph, src_node, defn, cutoff=20
                        ))
                        
                        for path in paths[:2]:  # 只保存前2条路径
                            path_info = []
                            for node in path:
                                node_loc = _resolve_location(node.codeloc)
                                node_func = project.kb.functions.floor_func(node_loc) if node_loc else None
                                path_info.append({
                                    'atom': str(node.atom),
                                    'location': hex(node_loc) if node_loc else "?",
                                    'function_name': node_func.name if node_func else "unknown"
                                })
                            chain_info['dependency_paths'].append(path_info)
                            
                            if len(paths) <= 2:  # 打印简短路径
                                print(f"        路径: {' -> '.join([str(n.atom) for n in path])}")
                    
                    except nx.NetworkXNoPath:
                        pass
            
            operand_result['chains'].append(chain_info)
        
        result['operands'].append(operand_result)
    
    return result


# ========== 使用示例 ==========
if __name__ == "__main__":
    # 输入：只需要binary路径和sink地址
    result = trace_operands_from_address(
        binary_path="/root/test/test4",
        sink_address=0x4006A8,  # 算术指令地址
        max_depth=7,
        cross_function=True
    )
    
    if result:
        print("\n" + "="*70)
        print("定义链溯源结果:")
        print("="*70)
        print(f"目标地址: {result['sink_address']}")
        print(f"所在函数: {result['function']}")
        print(f"指令: {result['instruction']}")
        print(f"分析模式: {'跨函数分析' if result['cross_function'] else '单函数分析'}")
        
        # 如果是跨函数分析，打印调用链
        if result.get('call_chain'):
            print(f"\n【调用链信息】")
            print(f"分析起点: {result['analysis_start']}")
            print(f"调用链:")
            for i, func_info in enumerate(result['call_chain']):
                prefix = "  " * i
                print(f"{prefix}→ {func_info['function']} @ {func_info['address']}")
            
            print(f"\n📊 分析方法:")
            print(f"  • 在目标函数 {result['function']} 上使用单函数RDA (基于VEX IR)")
            print(f"  • 对于函数参数（来自调用者），自动向上追溯到调用者函数")
            print(f"  • 调用链: {' → '.join([f['function'] for f in result['call_chain']])}")
            print(f"  • 已实现多层递归追溯，可追溯到函数返回的常量值")
        
        for i, operand in enumerate(result['operands'], 1):
            print(f"\n操作数 #{i}: {operand['atom']}")
            print(f"  定义数: {operand['definition_count']}")
            
            for j, chain in enumerate(operand['chains'], 1):
                print(f"\n  定义链 #{j}:")
                print(f"    根定义: {chain['root_definition']}")
                print(f"    位置: {chain['root_location']}")
                print(f"    闭包大小: {chain['closure_size']}")
                print(f"    数据源数: {len(chain['source_definitions'])}")
                
                print(f"\n    源头定义:")
                # 只显示数据源（已过滤地址偏移）
                data_sources = [s for s in chain['source_definitions'] if s.get('type') == 'data_value']
                other_sources = [s for s in chain['source_definitions'] if s.get('type') not in ['data_value']]
                
                if data_sources:
                    for src in data_sources:
                        val_str = hex(src['value']) if 'value' in src else str(src['atom'])
                        print(f"      • {src['atom']} @ {src['location']} (值: {val_str})")
                
                if other_sources:
                    for src in other_sources:
                        # is_external表示ExternalCodeLocation（来自调用者的函数参数）
                        param_mark = " [来自调用者]" if src.get('is_external') else ""
                        print(f"      • {src['atom']} @ {src['location']}{param_mark}")
                        
                        # 【新增】如果有跨函数追溯的结果，显示
                        if 'traced_sources' in src and src['traced_sources']:
                            parent_func_name = src['traced_sources'][0].get('function', 'parent') if src['traced_sources'] else 'parent'
                            print(f"        ↓ 跨函数追溯 (在 {parent_func_name} 中):")
                            for traced in src['traced_sources']:
                                if traced['type'] == 'constant':
                                    val_hex = hex(traced['value']) if traced['value'] <= 0xFFFFFFFF else str(traced['value'])
                                    # 追溯到的常量（在父函数中传递给子函数）
                                    if 'traced_from' in traced:
                                        print(f"          ✓ 常量值 {val_hex} @ {traced['location']} (in {traced['traced_from']})")
                                    else:
                                        print(f"          ✓ 常量 {val_hex} @ {traced.get('location', '?')} (in {traced.get('function', '?')})")
                                elif traced['type'] == 'external_parameter':
                                    # 递归的外部参数（来自更上层的调用者）
                                    print(f"          ✓ 外部参数 {traced['atom']} @ {traced['location']} (in {traced.get('function', '?')})")
                                elif traced['type'] == 'register_or_memory':
                                    # 寄存器或内存源
                                    print(f"          ✓ {traced['atom']} @ {traced['location']} (in {traced.get('function', '?')})")
                                elif traced['type'] == 'function_return':
                                    # 如果是嵌套的函数返回（没能追溯到常量）
                                    if 'traced_from' in traced:
                                        print(f"          ✓ {traced['traced_from']}() 返回 {traced.get('function_name', '?')}() @ {traced['call_location']} (in {traced['in_function']})")
                                    else:
                                        print(f"          ✓ {traced['function_name']}() 的返回值 @ {traced['call_location']} (in {traced['in_function']})")
                
                if not data_sources and not other_sources:
                    print(f"      （无直接数据源，可能来自寄存器或内存）")
                
                if chain['dependency_paths']:
                    print(f"\n    依赖路径 (共{len(chain['dependency_paths'])}条):")
                    for k, path in enumerate(chain['dependency_paths'][:2], 1):
                        print(f"      路径{k}: {' -> '.join([p['atom'] for p in path])}")
