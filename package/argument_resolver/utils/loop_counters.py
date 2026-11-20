"""Local VEX evidence for the loop-counter noise filter."""

import re

import networkx as nx
import pyvex
from angr.errors import SimTranslationError


# Keep this heuristic separate from arithmetic range proofs.
MAX_COUNTER_STEP = 2
E = pyvex.IRExpr
S = pyvex.IRStmt
_CAST = re.compile(r"Iop_(\d+)[US]?to(\d+)$")


def counter_step(expr):
    """Return the signed displacement and the unmodified operand."""
    if not isinstance(expr, E.Binop) or not expr.op.startswith(("Iop_Add", "Iop_Sub")):
        return None
    left, right = expr.args
    if isinstance(left, E.Const) and expr.op.startswith("Iop_Add"):
        left, right = right, left
    if not isinstance(right, E.Const) or isinstance(left, E.Const):
        return None
    width = right.con.size
    if expr.op not in (f"Iop_Add{width}", f"Iop_Sub{width}"):
        return None
    sign = 1 << (width - 1)
    delta = (right.con.value ^ sign) - sign
    return (-delta if expr.op.startswith("Iop_Sub") else delta), left


def _base(analyzer, expr, width=1, stop=None):
    """Follow SSA copies and casts preserving at least the low width bits."""
    stmts = analyzer.block.vex.statements
    while True:
        if isinstance(expr, E.RdTmp):
            if expr.tmp == stop:
                break
            index = analyzer.def_tmp.get(expr.tmp)
            if index is None or not isinstance(stmts[index], S.WrTmp):
                break
            expr = stmts[index].data
        elif isinstance(expr, E.Unop):
            cast = _CAST.fullmatch(expr.op)
            if not cast or min(map(int, cast.groups())) < width:
                break
            expr = expr.args[0]
        else:
            break
    return expr


def _stack_slot(analyzer, addr):
    addr = _base(analyzer, addr, analyzer.arch.bits)
    displacement = 0
    step = counter_step(addr)
    if step:
        displacement, addr = step
        addr = _base(analyzer, addr, analyzer.arch.bits)
    if isinstance(addr, E.Get) and (addr.offset == analyzer.sp_offset or
                                    addr.offset in analyzer.frame_pointer_offsets):
        return addr.offset, displacement
    return None


def _register_overlap(stmt, offset, size, tyenv):
    return isinstance(stmt, S.Put) and (stmt.offset < offset + size and
                                        offset < stmt.offset + stmt.data.result_size(tyenv) // 8)


def is_counter_update(analyzer, index, variable, test, guard, body, project):
    """Require one writeback, an unchanged storage location, and a comparison."""
    ir = analyzer.block.vex
    update = ir.statements[index]
    width = update.data.result_size(ir.tyenv)
    origin = _base(analyzer, variable, width)
    stack = isinstance(origin, E.Load)
    if stack:
        slot = _stack_slot(analyzer, origin.addr)
        if slot is None or origin.result_size(ir.tyenv) != width:
            return False
        reg, size = slot[0], analyzer.arch.bytes
    elif isinstance(origin, E.Get):
        reg, size = origin.offset, origin.result_size(ir.tyenv) // 8
    else:
        return False

    def is_result(expr):
        root = _base(analyzer, expr, width, stop=update.tmp)
        return isinstance(root, E.RdTmp) and root.tmp == update.tmp

    wrote = False
    for pos, stmt in enumerate(ir.statements):
        if isinstance(stmt, S.Exit) and not wrote:
            # A write in a conditional delay slot may only run on one edge.
            return False
        if _register_overlap(stmt, reg, size, ir.tyenv):
            if stack or stmt.offset != reg or stmt.data.result_size(ir.tyenv) < width:
                return False
        elif stack and isinstance(stmt, S.Store):
            dest = _stack_slot(analyzer, stmt.addr)
            store_width = stmt.data.result_size(ir.tyenv)
            if dest and dest[0] == slot[0] and (dest[1] + store_width // 8 <= slot[1]
                                                 or slot[1] + width // 8 <= dest[1]):
                if is_result(stmt.data):
                    return False
                continue
            if dest != slot or stmt.end != origin.end or store_width != width:
                return False
        elif isinstance(stmt, S.Store) and is_result(stmt.data):
            return False
        elif isinstance(stmt, (S.StoreG, S.CAS, S.PutI)) or (stack and isinstance(stmt, S.LoadG)):
            return False
        else:
            continue
        if wrote or pos <= index or not is_result(stmt.data):
            return False
        wrote = True
    if not wrote:
        return False

    def clobbers_storage(other):
        return any(_register_overlap(stmt, reg, size, other.tyenv)
                   or isinstance(stmt, (S.Dirty, S.CAS, S.LLSC, S.PutI))
                   or (stack and isinstance(stmt, (S.Store, S.StoreG)))
                   for stmt in other.statements)

    for node in body:
        if not node.size:
            return False
        try:
            other = project.factory.block(node.addr, size=node.size).vex
        except SimTranslationError:
            return False
        if (other.jumpkind != "Ijk_Boring" or not other.statements
                or any(isinstance(stmt, S.Exit) for stmt in other.statements)
                or clobbers_storage(other)):
            return False

    if test is not analyzer:
        # A split test reads the register/slot after the predecessor's write.
        if clobbers_storage(test.block.vex):
            return False
    comparison = _base(test, guard)
    if not isinstance(comparison, E.Binop) or not comparison.op.startswith("Iop_Cmp"):
        return False
    for arg in comparison.args:
        if arg.result_size(test.tyenv) < width:
            continue
        if test is analyzer and is_result(arg):
            return True
        # Flag lowering may compare the pre-update value, e.g. SUBS/BNE.
        source = _base(test, arg, width)
        if stack and isinstance(source, E.Load):
            if (source.result_size(test.tyenv) == width and source.end == origin.end
                    and _stack_slot(test, source.addr) == slot):
                return True
        elif isinstance(source, E.Get) and source.offset == reg and not stack:
            return True
    return False


class LoopBranches:
    """Find simple loops in the existing function CFG, lazily per candidate."""

    def __init__(self, function):
        self.function = function
        self.nodes = None
        self.cache = {}
        self.components = None

    def branch(self, analyzer, project):
        block = analyzer.block
        ir = block.vex
        if ir.jumpkind != "Ijk_Boring" or not isinstance(ir.next, E.Const):
            return None
        exits = [s for s in ir.statements if isinstance(s, S.Exit)]
        test = analyzer
        test_block = None
        if not exits:
            node = self.node(block.addr)
            if node is None:
                return None
            successors = list(self.function.graph.successors(node))
            if len(successors) != 1 or successors[0].addr != ir.next.con.value:
                return None
            target = successors[0]
            if not target.size or self.function.graph.out_degree(target) != 2:
                return None
            try:
                test_block = project.factory.block(target.addr, size=target.size)
                ir = test_block.vex
            except SimTranslationError:
                return None
            exits = [s for s in ir.statements if isinstance(s, S.Exit)]
        if (len(exits) != 1 or not isinstance(ir.next, E.Const)
                or ir.jumpkind != "Ijk_Boring" or exits[0].jumpkind != "Ijk_Boring"):
            return None
        targets = frozenset((ir.next.con.value, exits[0].dst.value))
        body = self.body(ir.addr, targets)
        if body is None or (test_block is not None and not any(n.addr == block.addr for n in body)):
            return None
        if test_block is not None:
            test = type(analyzer)(test_block, analyzer.arch)
        return test, exits[0].guard, [n for n in body if n.addr != block.addr]

    def node(self, addr):
        if self.nodes is None:
            self.nodes = {node.addr: node for node in self.function.graph}
        return self.nodes.get(addr)

    def body(self, addr, targets):
        key = (addr, targets)
        if key not in self.cache:
            self.cache[key] = self._find_body(addr, targets)
        return self.cache[key]

    def _find_body(self, addr, targets):
        graph = self.function.graph
        latch = self.node(addr)
        if latch is None:
            return None
        successors = list(graph.successors(latch))
        if len(successors) != 2 or {node.addr for node in successors} != targets:
            return None
        # Exactly one successor can reach the latch again. This excludes
        # internal conditionals even if one arm rejoins through several paths.
        if self.components is None:
            self.components = {node: number for number, group in
                               enumerate(nx.strongly_connected_components(graph)) for node in group}
        inside = [node for node in successors if self.components[node] == self.components[latch]]
        if len(inside) != 1:
            return None
        node = inside[0]
        path = []
        while node != latch:
            if graph.out_degree(node) != 1:
                return None
            path.append(node)
            node = next(iter(graph.successors(node)))
        return path
