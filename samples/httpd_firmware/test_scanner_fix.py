"""Regression checks using real ELF/VEX, without LLM requests."""
import json
from pathlib import Path
import unittest
import contextlib
import io

from argument_resolver.utils.integer_overflow import build_project, IntegerOverflowScanner
from argument_resolver.utils.integer_overflow_detection import _filter_constant_sinks
from argument_resolver.utils.width_screening import screen_by_width
from argument_resolver.utils.llm_overflow_analyzer import SinkInput, _build_step_prompt
from argument_resolver.utils.test_trace import trace_operands_from_address

ROOT = Path('/root/mango_0/samples/httpd_firmware')


class ScannerRegression(unittest.TestCase):
    def test_single_function_trace_without_handler(self):
        binary = str(ROOT / 'bin/cedar_router_httpd')
        project = build_project(binary)
        sinks = IntegerOverflowScanner(project).scan(function_names=['plan_upload'])
        sink = next(s for s in sinks if s.vex_op == 'Iop_Mul32')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = trace_operands_from_address(binary, sink.ins_addr, cross_function=False)
        self.assertIsInstance(result, dict)
        self.assertEqual(result['function'], 'plan_upload')

    def test_stack_updates_are_not_value_sinks(self):
        project = build_project(str(ROOT / 'bin/cedar_router_httpd'))
        sinks = IntegerOverflowScanner(project).scan()
        stack = [s for s in sinks if s.notes['updates_sp']]
        self.assertTrue(stack)
        self.assertTrue(all(s.classification != 'value_arith' for s in stack))

    def test_three_vulnerable_operations_survive(self):
        cases = json.loads((ROOT / 'manifest.json').read_text())
        for case in cases:
            if not case['expected_cwe190']:
                continue
            with self.subTest(binary=case['binary']):
                binary = str(ROOT / 'bin' / case['binary'])
                project = build_project(binary)
                candidates = IntegerOverflowScanner(project).scan(function_names=[case['target_function']])
                operation = 'Iop_Mul32' if case['operation'] == 'mul' else 'Iop_Add32'
                matches = [s for s in candidates if s.vex_op == operation]
                self.assertTrue(matches)
                for sink in matches:
                    self.assertEqual(sink.classification, 'value_arith')
                    self.assertFalse(sink.notes['looks_like_addr'])
                    self.assertTrue(sink.notes['used_as_store_value'])
                self.assertTrue(_filter_constant_sinks(binary, screen_by_width(matches)))
                addresses = [s for s in candidates if s.notes['used_as_addr'] and not s.notes['used_as_store_value']]
                self.assertTrue(addresses)
                self.assertTrue(all(s.classification != 'value_arith' for s in addresses))

    def test_prompt_binds_target_in_caller_context(self):
        sink = SinkInput(2, 'sink_2.json', {'sink_function': 'query_u32', 'sink_address': '0x401478',
                                         'instruction': 'lea rdx, [rax + 1]'})
        prompt = _build_step_prompt(sink, {}, 'p = p + 1;', 'dispatch_request', 0)
        self.assertIn('function=query_u32', prompt)
        self.assertIn('This snippet is the target function: False', prompt)
        self.assertIn('site=0x401478', prompt)


if __name__ == '__main__':
    unittest.main()
