"""Prove literal operand pairs on direct control flow before running per-sink RDA."""
from collections import defaultdict, deque
from dataclasses import replace
import logging

from angr.errors import SimTranslationError
from pyvex import IRExpr as E, IRStmt as S

from argument_resolver.utils.width_screening import WIDTH_STATUS_NO, assess_width_status

LOG = logging.getLogger(__name__)


def _literal(expr, temps, registers, tyenv):
    if isinstance(expr, E.Const) and isinstance(expr.con.value, int):
        return expr.con.value
    if isinstance(expr, E.RdTmp):
        return temps.get(expr.tmp)
    if isinstance(expr, E.Get):
        return registers.get((expr.offset, expr.result_size(tyenv)))
    return None


def _transfer(ir, incoming, candidates, safe):
    registers = incoming.copy()
    temps = {}
    exits = []
    for index, stmt in enumerate(ir.statements):
        if isinstance(stmt, S.WrTmp):
            sink = candidates.get(index)
            if (sink is not None and isinstance(stmt.data, E.Binop)
                    and stmt.data.op == sink.vex_op and len(sink.operand_states) == 2):
                values = [_literal(arg, temps, registers, ir.tyenv) for arg in stmt.data.args]
                if None not in values:
                    states = tuple(replace(state, origin="const", unsigned_bounds=(v, v))
                                   for state, v in zip(sink.operand_states, values))
                    if assess_width_status(replace(sink, operand_states=states))[0] == WIDTH_STATUS_NO:
                        safe.add((sink.function_addr, sink.block_addr, index))
            temps[stmt.tmp] = _literal(stmt.data, temps, registers, ir.tyenv)
        elif isinstance(stmt, S.Put):
            size = stmt.data.result_size(ir.tyenv)
            end = stmt.offset + (size + 7) // 8
            value = _literal(stmt.data, temps, registers, ir.tyenv)
            for offset, bits in list(registers):
                if offset < end and stmt.offset < offset + (bits + 7) // 8:
                    del registers[offset, bits]
            if value is not None:
                registers[stmt.offset, size] = value
        elif isinstance(stmt, S.Exit):
            exits.append((stmt.dst.value, registers.copy()))
        elif not isinstance(stmt, (S.IMark, S.NoOp, S.Store)):
            registers.clear()
    if ir.jumpkind == "Ijk_Boring":
        exits.append((ir.next.con.value, registers))
    return exits


def _safe_sites(project, function, candidates):
    if function.get_call_sites():
        return set()
    try:
        blocks = {block.addr: block.vex for block in function.blocks}
    except SimTranslationError:
        return set()
    if function.addr not in blocks:
        return set()
    cfg = project.kb.cfgs.get_most_accurate()
    if cfg is None:
        return set()

    # Validate all exits before trusting a join. An indirect jump or missing
    # block can introduce an incoming path not represented by CFGFast.
    predecessors = defaultdict(set)
    for addr, ir in blocks.items():
        if ir.jumpkind not in ("Ijk_Ret", "Ijk_Boring"):
            return set()
        if ir.jumpkind == "Ijk_Boring" and not isinstance(ir.next, E.Const):
            return set()
        for stmt in ir.statements:
            if isinstance(stmt, S.Exit) and stmt.jumpkind != "Ijk_Boring":
                return set()
        for target in ir.constant_jump_targets:
            if target not in blocks:
                return set()
            predecessors[target].add(addr)

    entries = {function.addr}
    for addr in blocks:
        nodes = cfg.get_all_nodes(addr)
        if (not predecessors[addr] or len(nodes) != 1 or nodes[0].function_address != function.addr
                or any(p.addr not in predecessors[addr] or p.function_address != function.addr
                       for p in cfg.graph.predecessors(nodes[0]))):
            entries.add(addr)
    inputs = {addr: {} for addr in entries}
    pending = deque(entries)
    while pending:
        addr = pending.popleft()
        for target, facts in _transfer(blocks[addr], inputs[addr], {}, None):
            if target not in blocks:
                return set()
            if target in inputs:
                old = inputs[target]
                facts = {key: value for key, value in old.items() if facts.get(key) == value}
                if facts == old:
                    continue
            inputs[target] = facts
            pending.append(target)

    # Inspect only the converged states, including any loop backedges.
    safe = set()
    for addr, sites in candidates.items():
        if addr in inputs:
            _transfer(blocks[addr], inputs[addr], sites, safe)
    return safe


def screen_fixed_operands(project, screened):
    grouped = defaultdict(lambda: defaultdict(dict))
    for sink, _, _ in screened:
        grouped[sink.function_addr][sink.block_addr][sink.stmt_idx] = sink
    safe = set()
    for addr, candidates in grouped.items():
        safe.update(_safe_sites(project, project.kb.functions[addr], candidates))
    LOG.info("Fixed-operand screening: %d -> %d", len(screened), len(screened) - len(safe))
    return [item for item in screened
            if (item[0].function_addr, item[0].block_addr, item[0].stmt_idx) not in safe]
