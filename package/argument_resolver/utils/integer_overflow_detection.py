"""
High-level pipeline that combines the integer overflow scanner, operand origin
inspector, and tracing utilities to surface actionable sink information.

Workflow:
1. Scan the binary for arithmetic operations and keep the sinks that behave like
   ``value_arith`` (operations whose result escapes as a value).
2. Use :func:`arithmetic_operand_origin.analyze_arithmetic_operands` to drop
   sinks whose operands ultimately originate from compile-time constants.
3. Feed the remaining sinks into :func:`test_trace.trace_operands_from_address`
   to recover call-chain information.
4. Decompile every function that appears on the call-chain so the operator can
   audit the surrounding semantics without leaving Mango.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import logging
import json
import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import angr
from angr.errors import AngrError

from argument_resolver.utils.integer_overflow import (
    ArithmeticOperation,
    IntegerOverflowScanner,
    build_project,
)
from argument_resolver.utils.arithmetic_operand_origin import (
    analyze_arithmetic_operands,
)
from argument_resolver.utils.test_trace import trace_operands_from_address
from argument_resolver.utils.vex_helpers import function_has_dirty_blocks
from argument_resolver.utils.width_screening import screen_by_width


LOG = logging.getLogger(__name__)


@dataclass
class FunctionSource:
    """Hold decompiled text for a single function."""

    name: str
    address: int
    code: str


@dataclass
class TraceArtifact:
    """Wrapper for ``test_trace`` artefacts that we care about."""

    call_chain: List[Dict[str, str]] = field(default_factory=list)
    operands: List[Dict[str, object]] = field(default_factory=list)
    raw_result: Dict[str, object] = field(default_factory=dict)
    captured_output: str = ""


@dataclass
class SinkReport:
    """Complete report for a filtered arithmetic sink."""

    sink: ArithmeticOperation
    operand_origin: Dict[str, object]
    trace: Optional[TraceArtifact]
    decompiled_sources: List[FunctionSource]
    disassembly_context: List[Dict[str, object]]
    width_status: str
    width_reason: str


class FunctionDecompiler:
    """
    Thin cache around ``project.analyses.Decompiler`` so multiple sinks sharing
    the same function do not trigger duplicate analyses.
    """

    def __init__(self, project: angr.Project):
        self._project = project
        self._cache: Dict[int, FunctionSource] = {}

    def decompile(self, addr: int) -> Optional[FunctionSource]:
        if addr in self._cache:
            return self._cache[addr]

        func = self._project.kb.functions.get(addr)
        if func is None:
            LOG.warning("Function at %s is unknown to angr; skipping decompilation", hex(addr))
            return None

        if function_has_dirty_blocks(func):
            code = f"// Skipped decompilation for {func.name}: contains VEX Dirty/LLSC/MBE statements"
            source = FunctionSource(name=func.name, address=addr, code=code)
            self._cache[addr] = source
            return source

        try:
            analysis = self._project.analyses.Decompiler(func)
            code = analysis.codegen.text if analysis.codegen is not None else ""
        except AngrError as exc:
            code = f"// Failed to decompile {func.name}: {exc}"
        except Exception as exc:  # pragma: no cover - defensive catch
            code = f"// Unexpected failure while decompiling {func.name}: {exc}"

        if not code:
            code = "// No decompiled text available"

        source = FunctionSource(name=func.name, address=addr, code=code)
        self._cache[addr] = source
        return source


def _parse_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        value = value.strip()
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except (AttributeError, ValueError):
        return None


def _collect_value_sinks(
    project: angr.Project,
    *,
    bit_widths: Optional[Iterable[int]],
    op_names: Optional[Iterable[str]],
    function_names: Optional[Sequence[str]],
    function_addrs: Optional[Sequence[int]],
    min_addr: Optional[int],
    max_addr: Optional[int],
) -> List[ArithmeticOperation]:
    scanner = IntegerOverflowScanner(
        project, bit_widths=bit_widths, op_names=op_names
    )
    sinks = scanner.scan(
        function_names=function_names,
        function_addrs=function_addrs,
        min_addr=min_addr,
        max_addr=max_addr,
    )
    value_sinks = [
        sink for sink in sinks if sink.classification == "value_arith" and sink.ins_addr
    ]
    LOG.info("Scanner discovered %d arithmetic sinks (%d value_arith)", len(sinks), len(value_sinks))
    return value_sinks


def _has_constant_operand(origin_report: Dict[str, object]) -> bool:
    operands = origin_report.get("operands") or []
    for operand in operands:
        for definition in operand.get("definitions", []):
            for source in definition.get("sources", []):
                if source.get("origin") == "constant":
                    return True
    return False


def _filter_constant_sinks(
    binary_path: str, sinks: Sequence[Tuple[ArithmeticOperation, str, str]]
) -> List[Tuple[ArithmeticOperation, Dict[str, object], str, str]]:
    filtered: List[Tuple[ArithmeticOperation, Dict[str, object], str, str]] = []
    before = len(sinks)
    immediate_after = 0
    for sink, width_status, width_reason in sinks:
        if sink.ins_addr is None:
            continue
        try:
            origin_report = analyze_arithmetic_operands(binary_path, sink.ins_addr)
        except Exception as exc:  # pragma: no cover - analysis failures
            LOG.warning(
                "Failed to analyze operands for %s @ %s: %s",
                sink.function,
                hex(sink.ins_addr),
                exc,
            )
            continue
        if origin_report.get("immediate_add_one"):
            LOG.debug(
                "Dropping %s @ %s because it is add-immediate #1",
                sink.function,
                hex(sink.ins_addr),
            )
            continue
        immediate_after += 1
        if _has_constant_operand(origin_report):
            LOG.debug(
                "Dropping %s @ %s because it uses constant operands",
                sink.function,
                hex(sink.ins_addr),
            )
            continue
        filtered.append((sink, origin_report, width_status, width_reason))
    LOG.info("Filtered sinks: kept %d / %d", len(filtered), len(sinks))
    LOG.info("Immediate-add-one filtering: %d -> %d", before, immediate_after)
    LOG.debug("Constant filtering: %d -> %d", immediate_after, len(filtered))
    return filtered


def _run_trace(
    binary_path: str, sink_addr: int, max_depth: int, cross_function: bool
) -> Tuple[Optional[TraceArtifact], str]:
    buffer = io.StringIO()
    trace_result = None
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        trace_result = trace_operands_from_address(
            binary_path=binary_path,
            sink_address=sink_addr,
            max_depth=max_depth,
            cross_function=cross_function,
        )
    captured = buffer.getvalue()
    if trace_result is None:
        return None, captured
    artifact = TraceArtifact(
        call_chain=list(trace_result.get("call_chain") or []),
        operands=list(trace_result.get("operands") or []),
        raw_result=trace_result,
        captured_output=captured,
    )
    return artifact, captured


def _collect_function_addresses(
    call_chain: Sequence[Dict[str, str]], sink: ArithmeticOperation
) -> List[int]:
    ordered: List[int] = []
    seen = set()
    for entry in call_chain:
        addr = _parse_int(entry.get("address"))
        if addr is None or addr in seen:
            continue
        ordered.append(addr)
        seen.add(addr)
    if sink.function_addr not in seen:
        ordered.append(sink.function_addr)
    return ordered


def _decompile_chain(
    decompiler: FunctionDecompiler,
    call_chain: Sequence[Dict[str, str]],
    sink: ArithmeticOperation,
) -> List[FunctionSource]:
    addresses = _collect_function_addresses(call_chain, sink)
    sources: List[FunctionSource] = []
    for addr in addresses:
        source = decompiler.decompile(addr)
        if source:
            sources.append(source)
    return sources


def run_detection(
    binary_path: str,
    *,
    bit_widths: Optional[Iterable[int]] = None,
    op_names: Optional[Iterable[str]] = None,
    function_names: Optional[Sequence[str]] = None,
    function_addrs: Optional[Sequence[int]] = None,
    min_addr: Optional[int] = None,
    max_addr: Optional[int] = None,
    max_depth: int = 7,
    cross_function: bool = True,
    limit: Optional[int] = None,
) -> List[SinkReport]:
    """
    Execute the detection pipeline and return structured sink reports.
    """

    project = build_project(binary_path)
    value_sinks = _collect_value_sinks(
        project,
        bit_widths=bit_widths,
        op_names=op_names,
        function_names=function_names,
        function_addrs=function_addrs,
        min_addr=min_addr,
        max_addr=max_addr,
    )
    if limit is not None:
        value_sinks = value_sinks[:limit]

    width_screened = screen_by_width(value_sinks)
    if not width_screened:
        LOG.info("No sinks survived width screening.")
        return []

    filtered_sinks = _filter_constant_sinks(binary_path, width_screened)
    if not filtered_sinks:
        return []

    reports: List[SinkReport] = []
    decompiler = FunctionDecompiler(project)
    for sink, origin_report, width_status, width_reason in filtered_sinks:
        trace_artifact, _ = _run_trace(
            binary_path, sink.ins_addr, max_depth, cross_function
        )
        call_chain = trace_artifact.call_chain if trace_artifact else []
        sources = _decompile_chain(decompiler, call_chain, sink)
        disassembly_context = _build_disassembly_context(project, sink)
        reports.append(
            SinkReport(
                sink=sink,
                operand_origin=origin_report,
                trace=trace_artifact,
                decompiled_sources=sources,
                disassembly_context=disassembly_context,
                width_status=width_status,
                width_reason=width_reason,
            )
        )
    return reports


def _format_call_chain(call_chain: Sequence[Dict[str, str]]) -> str:
    if not call_chain:
        return "Call chain unavailable"
    parts = [f"{entry.get('function')}@{entry.get('address')}" for entry in call_chain]
    return " -> ".join(parts)


def _build_disassembly_context(
    project: angr.Project, sink: ArithmeticOperation, before: int = 5, after: int = 5
) -> List[Dict[str, object]]:
    if sink.ins_addr is None:
        return []
    block_addr = sink.block_addr if sink.block_addr is not None else sink.ins_addr
    try:
        block = project.factory.block(block_addr)
    except Exception:
        try:
            block = project.factory.block(sink.ins_addr)
        except Exception:
            return []

    insns = []
    capstone_block = getattr(block, "capstone", None)
    if capstone_block is not None:
        insns = list(getattr(capstone_block, "insns", []) or [])
    if not insns:
        disassembly = getattr(block, "disassembly", None)
        if disassembly is not None:
            insns = list(getattr(disassembly, "insns", []) or [])
    if not insns:
        return []

    entries: List[Tuple[int, str]] = []
    for insn in insns:
        text = f"{insn.mnemonic} {insn.op_str}".strip()
        entries.append((insn.address, text))

    sink_index = None
    for idx, (addr, _) in enumerate(entries):
        if addr == sink.ins_addr:
            sink_index = idx
            break
    if sink_index is None:
        try:
            fallback_block = project.factory.block(sink.ins_addr)
        except Exception:
            return []
        fallback_insns = []
        capstone_block = getattr(fallback_block, "capstone", None)
        if capstone_block is not None:
            fallback_insns = list(getattr(capstone_block, "insns", []) or [])
        if not fallback_insns:
            disassembly = getattr(fallback_block, "disassembly", None)
            if disassembly is not None:
                fallback_insns = list(getattr(disassembly, "insns", []) or [])
        if not fallback_insns:
            return []
        entries = [
            (insn.address, f"{insn.mnemonic} {insn.op_str}".strip())
            for insn in fallback_insns
        ]
        sink_index = 0

    start = max(0, sink_index - before)
    end = min(len(entries), sink_index + after + 1)
    context = []
    for addr, text in entries[start:end]:
        context.append(
            {
                "address": hex(addr),
                "text": text,
                "is_sink": addr == sink.ins_addr,
            }
        )
    return context


def _print_reports(reports: Sequence[SinkReport]) -> None:
    if not reports:
        print("No value_arith sinks survived the constant-operand filter.")
        return

    for idx, report in enumerate(reports, 1):
        sink = report.sink
        ins_addr = hex(sink.ins_addr) if sink.ins_addr is not None else "?"
        print(f"\n=== Sink #{idx}: {sink.function} @ {ins_addr} ({sink.vex_op}) ===")
        print(f"Instruction: {report.operand_origin.get('instruction')}")
        print(_format_call_chain(report.trace.call_chain if report.trace else []))
        print(f"Width status: {report.width_status} ({report.width_reason})")

        if not report.decompiled_sources:
            print("No decompiled sources were produced for this sink.")
            continue

        print("\n--- Decompiled functions along the call chain ---")
        for source in report.decompiled_sources:
            print(f"\n[{source.name} @ {hex(source.address)}]")
            print(source.code.rstrip())


def save_sink_reports(reports: Sequence[SinkReport], output_dir: str) -> List[str]:
    if not reports:
        return []
    os.makedirs(output_dir, exist_ok=True)
    paths = []
    for idx, report in enumerate(reports, 1):
        sink = report.sink
        sink_addr = hex(sink.ins_addr) if sink.ins_addr is not None else None
        call_chain = report.trace.call_chain if report.trace else []
        call_chain_functions = [entry.get("function") for entry in call_chain if entry.get("function")]
        data = {
            "sink_index": idx,
            "sink_address": sink_addr,
            "sink_function": sink.function,
            "instruction": report.operand_origin.get("instruction"),
            "call_chain_functions": call_chain_functions,
            "disassembly_context": report.disassembly_context,
            "decompiled_sources": [
                {
                    "name": source.name,
                    "address": hex(source.address),
                    "code": source.code,
                }
                for source in report.decompiled_sources
            ],
        }
        path = os.path.join(output_dir, f"sink_{idx}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
        paths.append(path)
    return paths


# Compatibility for existing callers.
_save_sink_reports = save_sink_reports


def _cli_args(argv: Optional[Sequence[str]] = None):
    parser = argparse.ArgumentParser(
        description="Aggregate integer_overflow, operand_origin, and test_trace outputs."
    )
    parser.add_argument("binary", help="Path to the binary under analysis.")
    parser.add_argument(
        "--bits",
        type=int,
        nargs="+",
        default=None,
        help="Bit-widths forwarded to the integer overflow scanner.",
    )
    parser.add_argument(
        "--ops",
        nargs="+",
        default=None,
        help="Operation names forwarded to the scanner (e.g. Add Sub Mul Shl).",
    )
    parser.add_argument(
        "--functions",
        nargs="+",
        default=None,
        help="Function names to inspect (defaults to all functions).",
    )
    parser.add_argument(
        "--function-addrs",
        nargs="+",
        default=None,
        help="Function addresses to inspect (hex accepted).",
    )
    parser.add_argument(
        "--min-addr",
        default=None,
        help="Lower bound for instruction addresses (hex or decimal).",
    )
    parser.add_argument(
        "--max-addr",
        default=None,
        help="Upper bound for instruction addresses (hex or decimal).",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=7,
        help="Maximum depth passed to test_trace when searching for call chains.",
    )
    parser.add_argument(
        "--no-cross-function",
        action="store_true",
        help="Disable cross-function tracing in test_trace.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process at most N sinks (useful for large binaries).",
    )
    parser.add_argument(
        "-results",
        "--results",
        dest="results",
        default=None,
        help="Directory to store per-sink JSON reports.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Verbosity of this driver script.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> None:
    args = _cli_args(argv)
    level = getattr(logging, args.log_level)
    if level < logging.ERROR:
        level = logging.ERROR
    logging.basicConfig(level=level)
    logging.getLogger().setLevel(level)
    function_addrs = None
    if args.function_addrs:
        function_addrs = [
            parsed
            for parsed in (_parse_int(value) for value in args.function_addrs)
            if parsed is not None
        ]
    min_addr = _parse_int(args.min_addr)
    max_addr = _parse_int(args.max_addr)

    reports = run_detection(
        args.binary,
        bit_widths=args.bits,
        op_names=args.ops,
        function_names=args.functions,
        function_addrs=function_addrs,
        min_addr=min_addr,
        max_addr=max_addr,
        max_depth=args.max_depth,
        cross_function=not args.no_cross_function,
        limit=args.limit,
    )
    _print_reports(reports)
    if args.results:
        _save_sink_reports(reports, args.results)


if __name__ == "__main__":  # pragma: no cover
    main()
