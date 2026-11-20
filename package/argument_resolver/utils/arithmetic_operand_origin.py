"""
Utility to inspect an arithmetic sink instruction and determine whether its operands
originate from external function inputs or locally defined constants.

The implementation borrows two ideas from Mango:
  - operand harvesting/debug logic that exists in ``test_trace.py``
  - data-flow inspection helpers such as ``transitive_closures_from_defs``.

Unlike ``test_trace.py`` this module focuses on a single function.  Given a concrete
sink address it runs a vanilla reaching-definition analysis on the surrounding
function and reports each operand's roots.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import angr
from capstone import CS_OP_MEM
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.atoms import Atom, MemoryLocation, Register
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.tag import ParameterTag, ReturnValueTag
from angr.knowledge_plugins.key_definitions import LiveDefinitions
from angr.code_location import ExternalCodeLocation
from archinfo import Endness
import pyvex

from argument_resolver.utils.transitive_closure import (
    get_constant_data,
    transitive_closures_from_defs,
)
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.vex_helpers import codeloc_hits_dirty
from argument_resolver.utils.integer_overflow_context import BinaryAnalysisContext


def _load_project(binary_path: str) -> angr.Project:
    """
    Load the binary, recover a CFG, and infer calling conventions so the function
    model contains the metadata that Mango expects.
    """

    project = angr.Project(binary_path, auto_load_libs=False)
    project.analyses.CFGFast(normalize=True, data_references=True)
    project.analyses.CompleteCallingConventions(
        recover_variables=True, analyze_callsites=True
    )
    return project


def _resolve_instruction(project: angr.Project, sink_address: int):
    block = project.factory.block(sink_address)
    try:
        ins_idx = block.instruction_addrs.index(sink_address)
    except ValueError as exc:
        msg = f"{hex(sink_address)} is not the start of an instruction"
        raise ValueError(msg) from exc
    return block.capstone.insns[ins_idx]


def _build_operand_atoms(insn, project: angr.Project) -> List[Atom]:
    """
    Translate capstone operands into angr atoms that can be fed into the RDA state.
    Only register operands are returned because single-function RDA is most precise
    on registers; additional atoms can be appended by callers if they need memory
    tracking.
    """

    atoms: List[Atom] = []
    arch = project.arch
    for operand in getattr(insn, "operands", []):
        if getattr(operand, "type", None) != 1:
            # Memory operands are intentionally skipped because they often represent
            # temporary stack slots that are already reached via the registers.
            continue
        reg_name = insn.reg_name(operand.reg)
        if reg_name in arch.registers:
            reg_offset, reg_size = arch.registers[reg_name]
            atoms.append(Register(reg_offset, reg_size))
    return atoms


def _extract_immediates(insn) -> List[int]:
    # Capstone-based immediate detection (TODO: port to VEX for arch-agnostic support).
    immediates: List[int] = []
    for operand in getattr(insn, "operands", []):
        if getattr(operand, "type", None) != 2:
            continue
        imm_val = getattr(operand, "imm", None)
        if imm_val is None:
            continue
        if isinstance(imm_val, int):
            immediates.append(imm_val)
    return immediates


def _add_memory_atoms_from_state(
    project: angr.Project, atoms: List[Atom], state
) -> List[Atom]:
    """
    Expand ``atoms`` with memory locations recovered from the current state.
    """

    seen = {
        (
            type(atom),
            getattr(atom, "reg_offset", None),
            getattr(atom, "addr", None),
        )
        for atom in atoms
    }
    extra_atoms: List[Atom] = []
    for atom in list(atoms):
        defs = state.get_definitions(atom)
        for definition in defs:
            if isinstance(definition.atom, MemoryLocation):
                key = (
                    type(definition.atom),
                    getattr(definition.atom, "reg_offset", None),
                    getattr(definition.atom, "addr", None),
                )
                if key not in seen:
                    seen.add(key)
                    extra_atoms.append(definition.atom)
    atoms.extend(extra_atoms)
    return atoms


def _collect_source_observation_points(
    project: angr.Project,
    rda,
    state,
    operand_atoms: List[Atom],
) -> Set[Tuple[str, int, int]]:
    """
    Identify closure root locations so we can observe their states in a follow-up RDA run.
    """

    points: Set[Tuple[str, int, int]] = set()
    for atom in operand_atoms:
        definitions = state.get_definitions(atom)
        if not definitions:
            continue
        closure_map = transitive_closures_from_defs(definitions, rda.dep_graph)
        for closure_graph in closure_map.values():
            for node in closure_graph.nodes():
                if closure_graph.in_degree(node) != 0:
                    continue
                loc = _format_location(project, node.codeloc) if node.codeloc else None
                if loc is None:
                    continue
                points.add(("insn", loc, OP_AFTER))
    return points


def _is_little_endian(endness) -> bool:
    if endness is None:
        return False
    if isinstance(endness, Endness):
        return endness == Endness.LE
    if isinstance(endness, str):
        return "LE" in endness.upper()
    return False


def _load_literal_from_memory(project: angr.Project, memloc: MemoryLocation) -> Optional[int]:
    addr = getattr(memloc, "addr", None)
    if isinstance(addr, int):
        concrete_addr = addr
    elif hasattr(addr, "concrete") and addr.concrete:
        concrete_addr = addr.concrete_value
    else:
        return None

    size = getattr(memloc, "size", None)
    if not size or size <= 0:
        return None

    try:
        data = project.loader.memory.load(concrete_addr, size)
    except KeyError:
        return None

    endness = getattr(memloc, "endness", None) or project.arch.memory_endness
    byteorder = "little" if _is_little_endian(endness) else "big"
    return int.from_bytes(data, byteorder=byteorder)


def _literal_from_multivalue(project: angr.Project, mv, state) -> Optional[int]:
    for value in Utils.get_values_from_multivalues(mv):
        try:
            definitions = list(LiveDefinitions.extract_defs(value))
        except Exception:
            continue
        for definition in definitions:
            if isinstance(definition.atom, MemoryLocation):
                literal_val = _load_literal_from_memory(project, definition.atom)
                if literal_val is not None:
                    return literal_val
    return None


def _expr_repr(expr, tmp_exprs, project):
    if expr is None:
        return None
    if isinstance(expr, pyvex.IRExpr.Const):
        return ("const", expr.con.value)
    if isinstance(expr, pyvex.IRExpr.RdTmp):
        return tmp_exprs.get(expr.tmp)
    if isinstance(expr, pyvex.IRExpr.Get):
        reg = project.arch.register_names.get(expr.offset, f"reg_{expr.offset}")
        return ("reg", reg)
    if isinstance(expr, pyvex.IRExpr.Binop):
        left = _expr_repr(expr.args[0], tmp_exprs, project)
        right = _expr_repr(expr.args[1], tmp_exprs, project)
        if left is None or right is None:
            return None
        return (expr.op, left, right)
    if isinstance(expr, pyvex.IRExpr.Unop):
        inner = _expr_repr(expr.args[0], tmp_exprs, project)
        if inner is None:
            return None
        return (expr.op, inner)
    if isinstance(expr, pyvex.IRExpr.Load):
        addr = _expr_repr(expr.addr, tmp_exprs, project)
        if addr is None:
            return None
        return ("load_addr", addr)
    return None


def _eval_vex_expr(
    project: angr.Project,
    expr,
    tyenv,
    stmts,
    tmp_defs,
    current_idx,
    depth=0,
    store_map=None,
    tmp_exprs=None,
) -> Optional[int]:
    if expr is None or depth > 20:
        return None
    if isinstance(expr, pyvex.IRExpr.Const):
        return expr.con.value
    if isinstance(expr, pyvex.IRExpr.RdTmp):
        entry = tmp_defs.get(expr.tmp)
        if not entry:
            return None
        stmt, idx = entry
        if idx >= current_idx:
            return None
        return _eval_vex_expr(project, stmt.data, tyenv, stmts, tmp_defs, idx, depth + 1, store_map, tmp_exprs)
    if isinstance(expr, pyvex.IRExpr.Binop):
        left = _eval_vex_expr(project, expr.args[0], tyenv, stmts, tmp_defs, current_idx, depth + 1, store_map, tmp_exprs)
        right = _eval_vex_expr(project, expr.args[1], tyenv, stmts, tmp_defs, current_idx, depth + 1, store_map, tmp_exprs)
        if left is None or right is None:
            return None
        op = expr.op
        if op.startswith("Iop_Add"):
            res = left + right
        elif op.startswith("Iop_Sub"):
            res = left - right
        elif op.startswith("Iop_And"):
            res = left & right
        else:
            return None
        size_bits = expr.result_size(tyenv)
        if size_bits:
            res &= (1 << size_bits) - 1
        return res
    if isinstance(expr, pyvex.IRExpr.Unop):
        arg = _eval_vex_expr(project, expr.args[0], tyenv, stmts, tmp_defs, current_idx, depth + 1, store_map, tmp_exprs)
        return arg
    if isinstance(expr, pyvex.IRExpr.Load):
        if store_map is not None and tmp_exprs is not None:
            addr_repr = _expr_repr(expr.addr, tmp_exprs, project)
            if addr_repr in store_map:
                return store_map[addr_repr]
        addr = _eval_vex_expr(project, expr.addr, tyenv, stmts, tmp_defs, current_idx, depth + 1, store_map, tmp_exprs)
        if addr is None:
            return None
        size_bits = expr.result_size(tyenv)
        size = max(size_bits // 8, 1)
        try:
            data = project.loader.memory.load(addr, size)
        except KeyError:
            return None
        byteorder = "little" if _is_little_endian(expr.end) else "big"
        return int.from_bytes(data, byteorder=byteorder)
    if isinstance(expr, pyvex.IRExpr.Get):
        return None
    return None


def _literal_from_vex(project: angr.Project, node: Definition) -> Optional[int]:
    codeloc = getattr(node, "codeloc", None)
    if codeloc is None or codeloc.block_addr is None or codeloc.stmt_idx is None:
        return None
    try:
        block = project.factory.block(codeloc.block_addr)
    except Exception:
        return None
    vex = block.vex
    stmts = vex.statements
    if codeloc.stmt_idx >= len(stmts):
        return None
    stmt = stmts[codeloc.stmt_idx]
    if not isinstance(stmt, pyvex.IRStmt.Put):
        return None
    tmp_defs = {}
    tmp_exprs = {}
    store_map = {}
    for idx, st in enumerate(stmts):
        if idx >= codeloc.stmt_idx:
            break
        if isinstance(st, pyvex.IRStmt.WrTmp):
            tmp_defs[st.tmp] = (st, idx)
            tmp_exprs[st.tmp] = _expr_repr(st.data, tmp_exprs, project)
        elif isinstance(st, pyvex.IRStmt.Store):
            addr_repr = _expr_repr(st.addr, tmp_exprs, project)
            if addr_repr is None:
                continue
            data_val = None
            if isinstance(st.data, pyvex.IRExpr.Const):
                data_val = st.data.con.value
            else:
                data_val = _eval_vex_expr(
                    project,
                    st.data,
                    vex.tyenv,
                    stmts,
                    tmp_defs,
                    idx,
                    depth=0,
                    store_map=store_map,
                    tmp_exprs=tmp_exprs,
                )
            if data_val is not None:
                store_map[addr_repr] = data_val
    return _eval_vex_expr(
        project,
        stmt.data,
        vex.tyenv,
        stmts,
        tmp_defs,
        codeloc.stmt_idx,
        depth=0,
        store_map=store_map,
        tmp_exprs=tmp_exprs,
    )


def _adjust_endian_values(values: List[int], atom_size: int, arch_endness: str) -> List[int]:
    byte_size = atom_size if atom_size else 0
    if arch_endness == Endness.BE:
        return values
    adjusted = []
    arch_is_little = _is_little_endian(arch_endness)
    if not arch_is_little or byte_size <= 0:
        return values
    for val in values:
        try:
            raw = val.to_bytes(byte_size, byteorder="big", signed=False)
            adjusted.append(int.from_bytes(raw, byteorder="little", signed=False))
        except OverflowError:
            adjusted.append(val)
    return adjusted


def _format_location(project: angr.Project, codeloc) -> Optional[int]:
    ins_addr = getattr(codeloc, "ins_addr", None)
    if ins_addr is not None:
        return ins_addr
    block = getattr(codeloc, "block_addr", None)
    if block is not None and hasattr(codeloc, "stmt_idx"):
        try:
            blk = project.factory.block(block)
            ins_addresses = blk.instruction_addrs
            if (
                codeloc.stmt_idx is not None
                and 0 <= codeloc.stmt_idx < len(ins_addresses)
            ):
                return ins_addresses[codeloc.stmt_idx]
        except Exception:
            pass
    return block


def _describe_tags(defn: Definition) -> Dict[str, Any]:
    tags: Dict[str, Any] = {}
    for tag in getattr(defn, "tags", []):
        if isinstance(tag, ParameterTag):
            tags.setdefault("parameters", []).append(
                {
                    "index": getattr(tag, "idx", None),
                    "function": hex(tag.function) if hasattr(tag, "function") else None,
                }
            )
        elif isinstance(tag, ReturnValueTag):
            tags.setdefault("returns", []).append(
                hex(tag.function) if hasattr(tag, "function") else None
            )
    return tags


def _normalize_constant(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if hasattr(value, "concrete_value"):
        try:
            return int(value.concrete_value)
        except Exception:
            return int(value.args[0])  # type: ignore[index]
    return str(value)


def _summarize_source(
    project: angr.Project,
    default_state,
    node: Definition,
    state_lookup: Dict[Tuple[str, int, int], Any],
) -> Optional[Dict[str, Any]]:
    loc_int = _format_location(project, node.codeloc) if node.codeloc else None
    observation_key = (
        ("insn", loc_int, OP_AFTER) if loc_int is not None else None
    )
    node_state = (
        state_lookup.get(observation_key, default_state)
        if observation_key is not None
        else default_state
    )
    mv = node_state.get_value_from_definition(node) if node_state else None
    if (
        mv is None
        and node_state is not None
        and isinstance(node.atom, Register)
    ):
        mv = node_state.registers.load(
            node.atom.reg_offset, size=node.atom.size
        )
    info: Dict[str, Any] = {
        "atom": str(node.atom),
        "location": hex(loc_int) if loc_int is not None else None,
        "is_external": isinstance(node.codeloc, ExternalCodeLocation),
        "tags": _describe_tags(node),
    }

    if node.codeloc and codeloc_hits_dirty(project, node.codeloc):
        info["origin"] = "unknown"
        info["note"] = "dirty_boundary"
        return info

    if mv is not None:
        const_vals = get_constant_data(node, mv, node_state)
        if const_vals and any(v is not None for v in const_vals):
            info["origin"] = "constant"
            normalized = [_normalize_constant(v) for v in const_vals if v is not None]
            info["values"] = normalized
            return info
        literal_from_mem = _literal_from_multivalue(project, mv, node_state)
        if literal_from_mem is not None:
            info["origin"] = "constant"
            info["values"] = [literal_from_mem]
            return info
        vex_literal = _literal_from_vex(project, node)
        if vex_literal is not None:
            info["origin"] = "constant"
            info["values"] = [vex_literal]
            return info
        # Fallback: registers that directly hold immediates may not be handled by
        # get_constant_data(), so pull concrete bitvectors directly.
        concrete_vals = Utils.get_concrete_value_from_int(mv)
        if concrete_vals:
            reg_size = getattr(node.atom, "size", None) or project.arch.bytes
            concrete_vals = _adjust_endian_values(
                concrete_vals, reg_size, project.arch.memory_endness
            )
            info["origin"] = "constant"
            info["values"] = concrete_vals
            return info

    if isinstance(node.atom, MemoryLocation):
        literal_val = _load_literal_from_memory(project, node.atom)
        if literal_val is not None:
            info["origin"] = "constant"
            info["values"] = [literal_val]
            return info

    if info["is_external"]:
        info["origin"] = "external_parameter"
        return info

    info["origin"] = "internal"
    return info


def _summarize_operand(
    project: angr.Project,
    rda,
    state,
    atom: Atom,
    state_lookup: Dict[Tuple[str, int, int], Any],
) -> Dict[str, Any]:
    definitions = state.get_definitions(atom)
    summary = {
        "atom": str(atom),
        "definition_count": len(definitions),
        "definitions": [],
    }
    if not definitions:
        return summary

    closures = transitive_closures_from_defs(definitions, rda.dep_graph)
    for defn, closure_graph in closures.items():
        source_nodes = [
            node for node in closure_graph.nodes() if closure_graph.in_degree(node) == 0
        ]
        seen_nodes = set(source_nodes)
        for literal_node in closure_graph.nodes():
            if (
                isinstance(literal_node.atom, MemoryLocation)
                and literal_node not in seen_nodes
            ):
                source_nodes.append(literal_node)
                seen_nodes.add(literal_node)

        sources = []
        for node in source_nodes:
            src_info = _summarize_source(project, state, node, state_lookup)
            if src_info:
                sources.append(src_info)

        summary["definitions"].append(
            {
                "definition": str(defn),
                "location": (
                    hex(loc)
                    if (defn.codeloc and (loc := _format_location(project, defn.codeloc)) is not None)
                    else None
                ),
                "sources": sources,
            }
        )
    return summary


def _inspect_arithmetic_instruction(binary_path, sink_address, context):
    project = context.project_for(binary_path) if context is not None else _load_project(binary_path)
    sink_function = project.kb.functions.floor_func(sink_address)
    if not sink_function:
        raise ValueError(f"Address {hex(sink_address)} is not inside a function")

    insn = _resolve_instruction(project, sink_address)
    base_atoms = _build_operand_atoms(insn, project)
    if not base_atoms and not any(op.type == CS_OP_MEM for op in insn.operands):
        raise ValueError(
            f"Instruction {insn.mnemonic} {insn.op_str} has no register or memory operands"
        )
    return project, sink_function, insn, base_atoms


def describe_arithmetic_instruction(
    binary_path: str, sink_address: int, *, context: Optional[BinaryAnalysisContext] = None
) -> Dict[str, Any]:
    """Decode the instruction used by CLI reports and apply operand eligibility checks."""
    _, _, insn, _ = _inspect_arithmetic_instruction(binary_path, sink_address, context)
    return {"instruction": f"{insn.mnemonic} {insn.op_str}"}


def analyze_arithmetic_operands(
    binary_path: str, sink_address: int, *, context: Optional[BinaryAnalysisContext] = None
) -> Dict[str, Any]:
    """Run function-local RDA and report definitions and sources for each operand."""
    project, sink_function, insn, base_atoms = _inspect_arithmetic_instruction(binary_path, sink_address, context)

    observation = ("insn", sink_address, OP_BEFORE)
    observation_points: Set[Tuple[str, int, int]] = {observation}
    rda = project.analyses.ReachingDefinitions(
        subject=sink_function,
        observation_points=set(observation_points),
        dep_graph=DepGraph(),
        max_iterations=4,
    )
    state = rda.observed_results.get(observation)
    if state is None:
        raise RuntimeError(f"Could not recover state for {hex(sink_address)}")

    operand_atoms = _add_memory_atoms_from_state(project, list(base_atoms), state)
    extra_points = _collect_source_observation_points(
        project, rda, state, operand_atoms
    )

    if extra_points:
        observation_points |= extra_points
        rda = project.analyses.ReachingDefinitions(
            subject=sink_function,
            observation_points=set(observation_points),
            dep_graph=DepGraph(),
            max_iterations=4,
        )
        state = rda.observed_results.get(observation)
        if state is None:
            raise RuntimeError(f"Could not recover state for {hex(sink_address)}")
        operand_atoms = _add_memory_atoms_from_state(project, list(base_atoms), state)

    immediates = _extract_immediates(insn)
    is_add_mnemonic = insn.mnemonic.lower().startswith("add")
    immediate_add_one = is_add_mnemonic and any(val == 1 for val in immediates)
    result = {
        "binary": Path(binary_path).name,
        "sink_address": hex(sink_address),
        "function": sink_function.name,
        "instruction": f"{insn.mnemonic} {insn.op_str}",
        "immediates": immediates,
        "immediate_add_one": immediate_add_one,
        "immediate_detection": "capstone",
        "operands": [],
    }

    state_lookup: Dict[Tuple[str, int, int], Any] = {}
    for obs in observation_points:
        obs_state = rda.observed_results.get(obs)
        if obs_state is not None:
            state_lookup[obs] = obs_state

    for atom in operand_atoms:
        result["operands"].append(
            _summarize_operand(project, rda, state, atom, state_lookup)
        )
    return result


def _parse_int(value: str) -> int:
    value = value.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value)


def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect an arithmetic sink and determine whether its operands "
            "originate from external parameters or constants."
        )
    )
    parser.add_argument("--binary", required=True, help="Path to the binary.")
    parser.add_argument(
        "--address",
        required=True,
        type=_parse_int,
        help="Instruction address (e.g., 0x400123).",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Print a human-readable summary instead of raw dict output.",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    result = analyze_arithmetic_operands(args.binary, args.address)
    if not args.pretty:
        print(result)
        return

    print(f"Binary      : {result['binary']}")
    print(f"Function    : {result['function']} @ {result['sink_address']}")
    print(f"Instruction : {result['instruction']}")
    for operand in result["operands"]:
        print(f"\nOperand {operand['atom']} ({operand['definition_count']} defs)")
        for defn in operand["definitions"]:
            print(f"  Def {defn['definition']} @ {defn['location']}:")
            if not defn["sources"]:
                print("    (no sources)")
                continue
            for source in defn["sources"]:
                origin = source.get("origin")
                loc = source.get("location")
                values = source.get("values")
                prefix = f"    - {origin} @ {loc}"
                if origin == "constant" and values:
                    printable = ", ".join(
                        hex(v) if isinstance(v, int) else str(v) for v in values
                    )
                    prefix += f" (values: {printable})"
                    print(prefix)
                    continue
                print(prefix)
                if values:
                    printable = ", ".join(hex(v) if isinstance(v, int) else str(v) for v in values)
                    print(f"        values: {printable}")


if __name__ == "__main__":
    main()
