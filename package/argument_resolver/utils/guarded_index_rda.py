"""Recover small value sets implied by VEX guards on the incoming CFG path."""

from dataclasses import dataclass

import claripy
import pyvex
from angr.engines.light import SpOffset
from angr.engines.vex.claripy.irop import operations
from angr.errors import SimError
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

from argument_resolver.utils.rda import CustomRDA


# A fifth model means the set is too large to materialize in RDA.
_MAX_VALUES = 4
_MAX_GUARD_BLOCKS = 6


@dataclass(frozen=True)
class _RelativeLoad:
    base: Register
    displacement: int
    size: int
    endness: str

    def resolve(self, state):
        base = state.get_values(self.base)
        ptr = base.one_value() if base is not None else None
        if ptr is None:
            return None
        addr = ptr + self.displacement
        if addr.concrete:
            return MemoryLocation(addr.concrete_value, self.size, endness=self.endness)
        offset = state.get_stack_offset(addr)
        if isinstance(offset, int):
            return MemoryLocation(SpOffset(state.arch.bits, offset), self.size, endness=self.endness)
        return None


class _GuardPath:
    """Track only scalar expressions and loads still live at the selected edge."""

    def __init__(self, arch):
        self.arch = arch
        self.registers = {}
        self.loads = {}
        self.conditions = []

    def _read(self, expr, temps, types):
        E = pyvex.IRExpr
        bits = expr.result_size(types)
        if isinstance(expr, E.Const):
            return claripy.BVV(expr.con.value, bits)
        if isinstance(expr, E.RdTmp):
            return temps.get(expr.tmp)
        if isinstance(expr, E.Get):
            reg = Register(expr.offset, bits // self.arch.byte_width)
            if reg not in self.registers:
                self.registers[reg] = claripy.BVS("guard_reg", bits)
            return self.registers[reg]
        if isinstance(expr, E.Load):
            addr = self._read(expr.addr, temps, types)
            if addr is None:
                return None
            key = (addr.cache_key, bits, expr.end)
            if key not in self.loads:
                self.loads[key] = claripy.BVS("guard_load", bits)
            return self.loads[key]
        if isinstance(expr, (E.Unop, E.Binop)) and expr.op in operations:
            args = [self._read(arg, temps, types) for arg in expr.args]
            if all(arg is not None for arg in args):
                return operations[expr.op].calculate(*args)
        return None

    def _put(self, reg, value):
        for old in tuple(self.registers):
            if old.reg_offset < reg.reg_offset + reg.size and reg.reg_offset < old.reg_offset + old.size:
                del self.registers[old]
        self.registers[reg] = value

    def follow(self, ir, target):
        S = pyvex.IRStmt
        if ir.jumpkind != "Ijk_Boring" or not isinstance(ir.next, pyvex.IRExpr.Const):
            return False
        exits = [stmt for stmt in ir.statements if isinstance(stmt, S.Exit)]
        if len(exits) > 1 or any(e.jumpkind != "Ijk_Boring" for e in exits):
            return False
        taken = exits[0].dst.value if exits else None
        other = ir.next.con.value
        if taken == other or target not in (taken, other):
            return False
        temps = {}
        for stmt in ir.statements:
            if isinstance(stmt, S.WrTmp):
                temps[stmt.tmp] = self._read(stmt.data, temps, ir.tyenv)
            elif isinstance(stmt, S.Put):
                if stmt.offset != self.arch.ip_offset:
                    size = stmt.data.result_size(ir.tyenv) // self.arch.byte_width
                    self._put(Register(stmt.offset, size), self._read(stmt.data, temps, ir.tyenv))
            elif isinstance(stmt, S.Store):
                # Any store can alias an earlier load. A subsequent load gets a
                # fresh symbol, even if it has the same addressing expression.
                self.loads.clear()
            elif isinstance(stmt, S.Exit):
                guard = self._read(stmt.guard, temps, ir.tyenv)
                if guard is None:
                    return False
                self.conditions.append(guard != 0 if target == taken else guard == 0)
                if target == taken:
                    break
            elif not isinstance(stmt, (S.IMark, S.NoOp)):
                return False
        return True

    def _locations(self, symbol):
        for (address_key, bits, endness), value in self.loads.items():
            if value is not symbol:
                continue
            address = address_key.ast
            size = bits // self.arch.byte_width
            if address.concrete:
                yield MemoryLocation(address.concrete_value, size, endness=endness)
            else:
                for reg, base in self.registers.items():
                    if base is None or base.size() != address.size():
                        continue
                    delta = claripy.simplify(address - base)
                    if delta.concrete:
                        yield _RelativeLoad(reg, delta.concrete_value, size, endness)
        for reg, value in self.registers.items():
            if value is symbol:
                yield reg

    def ranges(self):
        # Keep relations such as (end - index) together with bounds on end.
        # Asking for one extra model distinguishes exhaustiveness from a sample.
        if not self.conditions:
            return ()
        names = set().union(*(guard.variables for guard in self.conditions))
        solver = claripy.Solver(timeout=75)
        solver.add(self.conditions)
        regions = []
        seen = set()
        for symbol in (*self.loads.values(), *self.registers.values()):
            if (symbol is None or symbol.op != "BVS" or not symbol.variables <= names
                    or symbol.cache_key in seen):
                continue
            seen.add(symbol.cache_key)
            values = tuple(sorted(solver.eval(symbol, _MAX_VALUES + 1)))
            if 0 < len(values) <= _MAX_VALUES:
                regions.extend((loc, values) for loc in self._locations(symbol))
        return tuple(regions)


def _incoming_range(project, function, node):
    graph = function.graph
    path = []
    seen = {node}
    current = node
    while (len(path) < _MAX_GUARD_BLOCKS and current.addr != function.addr
           and current in graph and graph.in_degree(current) == 1):
        pred = next(graph.predecessors(current))
        if pred in seen or graph.out_degree(pred) not in (1, 2) or not getattr(pred, "size", None):
            break
        path.append((pred, current.addr))
        seen.add(pred)
        current = pred
    if not any(graph.out_degree(block) == 2 for block, _ in path):
        return ()
    guards = _GuardPath(project.arch)
    try:
        for block, target in reversed(path):
            if not guards.follow(project.factory.block(block.addr, size=block.size).vex, target):
                # Later edges can still impose new constraints after a call or
                # an unsupported statement. Forget all earlier relationships.
                guards = _GuardPath(project.arch)
        return guards.ranges()
    except (claripy.ClaripyError, SimError, pyvex.PyVEXError):
        return ()


def _add_alternatives(state, slot, indices):
    if isinstance(slot, _RelativeLoad):
        slot = slot.resolve(state)
    if slot is None:
        return state
    old = state.get_values(slot)
    if old is None or old.count() != 1 or 0 not in old or not any(v.symbolic for v in old[0]):
        return state
    values = MultiValues()
    bits = slot.size * state.arch.byte_width
    for val in old[0]:
        if val.size() != bits:
            return state
        values.add_value(0, val)
        if val.symbolic:
            solver = claripy.Solver(timeout=75)
            for i in indices:
                candidate = claripy.BVV(i, bits)
                try:
                    possible = solver.satisfiable(extra_constraints=(val == candidate,))
                except claripy.ClaripyError:
                    return state
                if possible:
                    values.add_value(0, candidate.annotate(*val.annotations))
    refined = state.copy()
    if isinstance(slot, Register):
        refined.registers.store(slot.reg_offset, values, size=slot.size)
    elif isinstance(slot.addr, SpOffset):
        addr = state.get_stack_address(state.stack_address(slot.addr.offset))
        refined.stack.store(addr, values, size=slot.size, endness=slot.endness)
    else:
        refined.memory.store(slot.addr, values, size=slot.size, endness=slot.endness)
    return refined


class GuardedIndexRDA(CustomRDA):
    def _run_on_node(self, node, state):
        function = getattr(self._graph_visitor, "function", None)
        if function is not None:
            cache = self._function_handler.guard_ranges
            key = (function.addr, node)
            if key not in cache:
                cache[key] = _incoming_range(self.project, function, node)
            for slot, indices in cache[key]:
                state = _add_alternatives(state, slot, indices)
        return super()._run_on_node(node, state)
