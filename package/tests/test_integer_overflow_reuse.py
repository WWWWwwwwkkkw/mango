"""Real-analysis regressions for per-binary initialization reuse.

Constructor spies execute the original angr analyses: the counts are the
expensive side effect this optimization must remove, not mocked results.
"""
from contextlib import contextmanager, ExitStack, redirect_stdout, redirect_stderr
import functools
import io
from pathlib import Path
import shutil
import subprocess
import struct
import tempfile
import unittest
from unittest.mock import patch

import angr
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.analyses.complete_calling_conventions import CompleteCallingConventionsAnalysis

from argument_resolver.utils.integer_overflow import build_project, IntegerOverflowScanner, IRSBUseDef
from argument_resolver.utils.integer_overflow_detection import run_detection
from argument_resolver.utils.arithmetic_operand_origin import analyze_arithmetic_operands
from argument_resolver.utils.test_trace import trace_operands_from_address
from argument_resolver.utils.integer_overflow_context import BinaryAnalysisContext
from argument_resolver.utils import integer_overflow_detection as detection


@contextmanager
def count_global_initializations(fail_first_vra=False, fail_after_vra=False):
    counts = {"project": 0, "cfg": 0, "vra": 0, "projects": []}
    with ExitStack() as patches:
        for cls, name in ((angr.Project, "project"), (CFGFast, "cfg"),
                          (CompleteCallingConventionsAnalysis, "vra")):
            original = cls.__init__

            def make_spy(original_init, label):
                @functools.wraps(original_init)
                def initialize(instance, *args, **kwargs):
                    # Decompiler clinic may request a function-scoped CC pass;
                    # the regression targets repeated full-binary preparation.
                    global_preparation = label != "vra" or not kwargs.get("skip_other_funcs", False)
                    if global_preparation:
                        counts[label] += 1
                    if label == "vra" and global_preparation and fail_first_vra and counts[label] == 1:
                        raise RuntimeError("injected global VRA preparation failure")
                    result = original_init(instance, *args, **kwargs)
                    if label == "vra" and global_preparation and fail_after_vra and counts[label] == 1:
                        # Simulate an initializer that mutates KB metadata and
                        # then raises: retry must not consume that partial KB.
                        function = instance.project.kb.functions.function(name="multiply_values")
                        function.prototype = "incomplete VRA metadata"
                        raise RuntimeError("injected failure after global VRA writes")
                    if label == "project":
                        counts["projects"].append(instance)
                    return result
                return initialize

            patches.enter_context(patch.object(cls, "__init__", make_spy(original, name)))
        yield counts


@unittest.skipUnless(shutil.which("gcc"), "arithmetic integration fixture requires gcc")
class IntegerOverflowReuseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        source = root / "arithmetic.c"
        source.write_text("""
#include <stdint.h>
__attribute__((noinline)) unsigned add_values(unsigned a, unsigned b) {
    return a + b;
}
__attribute__((noinline)) unsigned multiply_values(unsigned a, unsigned b) {
    return a * b;
}
int main(int argc, char **argv) {
    volatile unsigned a = (unsigned)argc;
    volatile unsigned b = (unsigned)(uintptr_t)argv;
    return (int)(add_values(a, b) ^ multiply_values(a, b));
}
""", encoding="utf-8")
        cls.binary = root / "arithmetic"
        subprocess.run(["gcc", "-O0", "-fno-pie", "-no-pie", "-fno-stack-protector",
                        str(source), "-o", str(cls.binary)], check=True, capture_output=True)
        cls.other_binary = root / "another_binary"
        shutil.copyfile(cls.binary, cls.other_binary)

    def detect(self, binary=None, **kwargs):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return run_detection(str(binary or self.binary),
                                 function_names=["add_values", "multiply_values"], **kwargs)

    def test_multiple_candidates_share_global_preparation(self):
        with count_global_initializations() as counts:
            reports = self.detect()
        self.assertEqual({report.sink.function for report in reports},
                         {"add_values", "multiply_values"})
        self.assertEqual(len(reports), 2)
        self.assertTrue(all(report.trace is not None for report in reports))
        self.assertTrue(all(report.decompiled_sources for report in reports))
        self.assertEqual((counts["project"], counts["cfg"], counts["vra"]), (1, 1, 1))

    def test_detection_collects_widths_only_for_returned_candidates(self):
        project = build_project(str(self.binary))
        functions = ["add_values", "multiply_values"]
        full = IntegerOverflowScanner(project).scan(function_names=functions)
        expected = [op for op in full if op.classification == "value_arith" and op.ins_addr]
        self.assertTrue(expected)
        self.assertGreater(len(full), len(expected))
        self.assertTrue(all(op.operand_states for op in full))
        with ExitStack() as stack:
            spies = []
            for name in ("operand_width_states", "followup_widens", "narrow_use_width"):
                spy = stack.enter_context(patch.object(IRSBUseDef, name, autospec=True,
                                                       side_effect=getattr(IRSBUseDef, name)))
                spies.append(spy)
            logs = stack.enter_context(self.assertLogs(detection.LOG, level="INFO"))
            actual = detection._collect_value_sinks(project, bit_widths=None, op_names=None,
                                                    function_names=functions, function_addrs=None,
                                                    min_addr=None, max_addr=None)
        self.assertEqual(actual, expected)
        self.assertIn(f"Scanner discovered {len(full)} arithmetic sinks ({len(expected)} value_arith)",
                      [record.getMessage() for record in logs.records])
        for spy in spies:
            self.assertEqual(spy.call_count, len(expected))

    def test_cli_report_mode_avoids_local_origin_analysis(self):
        full = self.detect()
        self.assertTrue(all(report.operand_origin["operands"] for report in full))
        with patch.object(detection, "analyze_arithmetic_operands",
                          wraps=analyze_arithmetic_operands) as origins:
            compact = self.detect(include_operand_origins=False)
        origins.assert_not_called()
        self.assertEqual([r.sink for r in compact], [r.sink for r in full])
        self.assertEqual(len(compact), 2)
        for old, new in zip(full, compact):
            self.assertEqual(new.operand_origin, {"instruction": old.operand_origin["instruction"]})
            self.assertEqual(new.trace.call_chain, old.trace.call_chain)
            self.assertEqual(new.disassembly_context, old.disassembly_context)
            self.assertEqual(new.decompiled_sources, old.decompiled_sources)

    def test_independent_runs_prepare_separate_projects(self):
        with count_global_initializations() as counts:
            first = self.detect(self.binary)
            second = self.detect(self.other_binary)
        self.assertEqual(len(first), 2)
        self.assertEqual(len(second), 2)
        self.assertEqual((counts["project"], counts["cfg"], counts["vra"]), (2, 2, 2))
        self.assertIsNot(counts["projects"][0], counts["projects"][1])
        self.assertEqual([Path(project.filename) for project in counts["projects"]],
                         [self.binary, self.other_binary])

    def test_repeated_detection_of_same_binary_has_fresh_analysis_state(self):
        with count_global_initializations() as counts:
            first = self.detect()
            second = self.detect()
        self.assertEqual(len(first), 2)
        self.assertEqual(len(second), 2)
        self.assertEqual((counts["project"], counts["cfg"], counts["vra"]), (2, 2, 2))
        self.assertIsNot(counts["projects"][0], counts["projects"][1])

    def test_helpers_reject_context_for_different_binary(self):
        project = build_project(str(self.binary))
        operations = IntegerOverflowScanner(project).scan(function_names=["add_values"])
        sink = next(operation for operation in operations if operation.classification == "value_arith")
        context = BinaryAnalysisContext(project)
        for helper in (analyze_arithmetic_operands, trace_operands_from_address):
            with self.subTest(helper=helper.__name__):
                with count_global_initializations() as counts:
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        with self.assertRaisesRegex(ValueError, "different binary"):
                            helper(str(self.other_binary), sink.ins_addr, context=context)
                self.assertEqual(counts["vra"], 0)

    def test_candidate_order_preserves_origins_and_call_chains(self):
        forward = self.detect()
        collect = detection._collect_value_sinks

        def reversed_candidates(*args, **kwargs):
            return list(reversed(collect(*args, **kwargs)))

        with patch.object(detection, "_collect_value_sinks", reversed_candidates):
            backward = self.detect()

        def signatures(reports):
            result = {}
            for report in reports:
                sources = frozenset(
                    (operand["atom"], source.get("atom"), source.get("location"),
                     source.get("origin"), source.get("is_external"))
                    for operand in report.operand_origin["operands"]
                    for definition in operand["definitions"]
                    for source in definition["sources"]
                )
                chain = tuple((entry["function"], entry["address"]) for entry in report.trace.call_chain)
                result[report.sink.ins_addr] = (report.sink.function, sources, chain, report.width_status)
            return result

        self.assertEqual(len(forward), 2)
        self.assertEqual(len(backward), 2)
        self.assertEqual(signatures(forward), signatures(backward))

    def test_empty_selection_does_not_initialize_vra(self):
        with count_global_initializations() as counts:
            reports = run_detection(str(self.binary), min_addr=0, max_addr=1)
        self.assertEqual(len(reports), 0)
        self.assertEqual((counts["project"], counts["cfg"], counts["vra"]), (1, 1, 0))

    def test_failed_vra_does_not_mark_partial_preparation_ready(self):
        with count_global_initializations(fail_first_vra=True) as counts:
            reports = self.detect()
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].sink.function, "multiply_values")
        self.assertEqual((counts["project"], counts["cfg"], counts["vra"]), (2, 2, 2))

    def test_failed_vra_discards_partially_written_knowledge_base(self):
        with count_global_initializations(fail_after_vra=True) as counts:
            reports = self.detect()
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].operand_origin["function"], "multiply_values")
        self.assertIsNotNone(reports[0].trace)
        self.assertEqual((counts["project"], counts["cfg"], counts["vra"]), (2, 2, 2))
        self.assertIsNot(counts["projects"][0], counts["projects"][1])

    def test_standalone_operand_and_trace_helpers_keep_their_loaders(self):
        project = build_project(str(self.binary))
        operations = IntegerOverflowScanner(project).scan(function_names=["add_values"])
        sink = next(operation for operation in operations if operation.classification == "value_arith")
        with count_global_initializations() as counts:
            origin = analyze_arithmetic_operands(str(self.binary), sink.ins_addr)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                trace = trace_operands_from_address(str(self.binary), sink.ins_addr)
        self.assertEqual(origin["function"], "add_values")
        self.assertIsNotNone(trace)
        self.assertEqual(trace["function"], "add_values")
        self.assertEqual((counts["project"], counts["cfg"], counts["vra"]), (2, 2, 2))


class MipsContextTests(unittest.TestCase):
    def test_context_is_architecture_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "mips32.elf"
            data = bytearray(0x10c)
            ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8)
            data[:52] = struct.pack("<16sHHIIIIIHHHHHH", ident, 2, 8, 1,
                                   0x400100, 52, 0, 0x50001001, 52, 32, 1, 40, 0, 0)
            data[52:84] = struct.pack("<IIIIIIII", 1, 0, 0x400000, 0x400000,
                                      len(data), len(data), 5, 0x1000)
            struct.pack_into("<III", data, 0x100, 0x00851021, 0x03e00008, 0)
            binary.write_bytes(data)
            with count_global_initializations() as counts:
                project = build_project(str(binary))
                context = BinaryAnalysisContext(project)
                self.assertIs(context.project_for(str(binary)), project)
                self.assertIs(context.project_for(str(binary)), project)
            self.assertEqual(project.arch.name, "MIPS32")
            self.assertEqual((counts["project"], counts["cfg"], counts["vra"]), (1, 1, 1))


if __name__ == "__main__":
    unittest.main()
