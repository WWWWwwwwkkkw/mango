"""Read evidence for the two VEX inputs of a reported arithmetic operation."""

import re
from functools import lru_cache
from itertools import product
from math import prod

from angr.engines.light import SpOffset
from angr.engines.vex.claripy.irop import operations
from angr.errors import SimError
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
import claripy
import pyvex

from argument_resolver.utils.utils import Utils


def _matching_operations(ir, addr, op):
    current = None
    for idx, stmt in enumerate(ir.statements):
        if isinstance(stmt, pyvex.IRStmt.IMark):
            current = stmt.addr
        elif (current == addr and isinstance(stmt, pyvex.IRStmt.WrTmp)
              and getattr(stmt.data, "op", None) == op):
            yield idx, stmt


def _input_symbols(handler):
    if handler is None:
        return set()
    marked = list(handler.env_access) + list(handler.keyword_access)
    for records in handler.fd_tracker.values():
        if isinstance(records, list):
            marked.extend(entry["val"] for entry in records)
    return {name for marker in marked for name in marker.variables if name != "TOP"}


def _whole_values(mv, bits):
    # A fragment at another offset is not a complete operand value.
    if mv is None or mv.count() != 1 or 0 not in mv:
        return ()
    return tuple(v for v in mv[0] if v.size() == bits)


def _operand_values(ir, stmt_index, state):
    """Interpret only the input expressions, against the existing OP_BEFORE snapshot."""
    statements = ir.statements
    defs = {s.tmp: i for i, s in enumerate(statements[:stmt_index]) if isinstance(s, pyvex.IRStmt.WrTmp)}
    E, S = pyvex.IRExpr, pyvex.IRStmt

    @lru_cache(None)
    def tmp_values(tmp):
        idx = defs[tmp]
        return read(statements[idx].data, idx)

    def read(expr, idx):
        bits = expr.result_size(ir.tyenv)
        if isinstance(expr, E.RdTmp):
            return tmp_values(expr.tmp)
        if isinstance(expr, E.Const):
            return (claripy.BVV(expr.con.value, bits),)
        if isinstance(expr, E.Get):
            size = bits // state.arch.byte_width
            for s in statements[:idx]:
                if isinstance(s, S.PutI) or (isinstance(s, S.Put) and s.offset < expr.offset + size
                        and expr.offset < s.offset + s.data.result_size(ir.tyenv) // state.arch.byte_width):
                    return ()
            return _whole_values(state.get_values(Register(expr.offset, size)), bits)
        if isinstance(expr, E.Load):
            if any(isinstance(s, (S.Store, S.StoreG, S.CAS, S.Dirty, S.LLSC)) for s in statements[:idx]):
                return ()
            values = []
            for ptr in read(expr.addr, idx):
                if state.is_top(ptr):
                    continue
                location = Utils.get_store_method_from_ptr(ptr, state)
                if not isinstance(location, (int, SpOffset, HeapAddress)):
                    continue
                if isinstance(location, SpOffset) and not isinstance(location.offset, int):
                    continue
                atom = MemoryLocation(location, bits // state.arch.byte_width, endness=expr.end)
                values.extend(_whole_values(state.get_values(atom), bits))
            return tuple(values)
        if isinstance(expr, (E.Unop, E.Binop)) and expr.op in operations:
            args = [read(a, idx) for a in expr.args]
            # Bound local evaluation at joins. Unknown evidence never excludes a sink.
            if prod(map(len, args)) > 64:
                return ()
            return tuple(operations[expr.op].calculate(*vs) for vs in product(*args))
        return ()

    def describe(expr):
        if isinstance(expr, E.RdTmp):
            return describe(statements[defs[expr.tmp]].data)
        if isinstance(expr, E.Get):
            return state.arch.translate_register_name(expr.offset, expr.result_size(ir.tyenv) // 8)
        if isinstance(expr, E.Load):
            return f"load{expr.result_size(ir.tyenv)}({describe(expr.addr)})"
        if isinstance(expr, (E.Unop, E.Binop)):
            return f"{expr.op[4:]}({', '.join(describe(a) for a in expr.args)})"
        return str(expr)

    return [(describe(arg), read(arg, stmt_index)) for arg in statements[stmt_index].data.args]


def input_evidence(project, sink, state, handler):
    result = {"status": "unknown", "vex_op": sink.vex_op, "operands": []}
    # Identify the scanner's exact operation, then lift only its instruction.
    # Earlier instructions in the original IRSB have already run at OP_BEFORE.
    try:
        block = project.kb.functions[sink.function_addr].get_block(sink.block_addr)
        original = list(_matching_operations(block.vex, sink.ins_addr, sink.vex_op))
        if len(original) != 1 or original[0][0] != sink.stmt_idx:
            return result
        ir = project.factory.block(sink.ins_addr, num_inst=1).vex
        matches = list(_matching_operations(ir, sink.ins_addr, sink.vex_op))
        if len(matches) != 1:
            return result
        operands = _operand_values(ir, matches[0][0], state)
    except (SimError, claripy.ClaripyError, KeyError):
        return result
    known = _input_symbols(handler)
    for index, (expression, values) in enumerate(operands):
        names = {name for v in values for name in v.variables}
        sources = sorted(n for n in names if n in known or re.fullmatch(r"ARGC|ARGV_[1-9]\d*", n))
        result["operands"].append({
            "index": index, "expression": expression, "sources": sources,
            "observed_values": sorted({v.concrete_value for v in values if v.concrete}),
        })
        if sources:
            result["status"] = "external_input"
    return result
