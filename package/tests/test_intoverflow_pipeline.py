"""Dependency-light integration tests; no network requests or API charges."""
import argparse
import ast
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from argument_resolver.analysis import integer_overflow as pipeline
from argument_resolver.utils import llm_overflow_analyzer as llm


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "binary"
        self.binary.write_bytes(b"test binary")
        parser = argparse.ArgumentParser()
        pipeline.add_cli_arguments(parser)
        self.args = parser.parse_args([])
        vars(self.args).update(bin_path=str(self.binary), result_path=str(self.root / "results"),
                               max_depth=7, log_level="ERROR", sink_category="intoverflow")
        self.detector = types.ModuleType("argument_resolver.utils.integer_overflow_detection")
        self.detector.run_detection = Mock(return_value=[1, 2])

        def save(reports, directory):
            Path(directory).mkdir(parents=True, exist_ok=True)
            paths = []
            for i in reports:
                path = Path(directory) / f"sink_{i}.json"
                path.write_text(json.dumps({"sink_address": hex(i), "sink_function": "f",
                    "instruction": "add", "decompiled_sources": [{"name": "f", "code": "int f() {}"}]}))
                paths.append(str(path))
            return paths
        self.detector.save_sink_reports = save
        self.addCleanup(patch.stopall)
        patch.dict(sys.modules, {self.detector.__name__: self.detector}).start()

    def summary(self):
        return json.loads((Path(self.args.result_path) / "intoverflow_results.json").read_text())

    @staticmethod
    def response(verdict="unknown"):
        return {"choices": [{"message": {"content": json.dumps({
            "meta": {}, "state": {}, "verdict": verdict, "confidence": "low", "vulnerable_ops": []})}}]}

    def test_complete_three_phase_and_isolated_rerun(self):
        self.args.llm_api_token = "test-secret"
        with patch.object(llm, "_post_json", return_value=self.response()) as request:
            self.assertEqual(pipeline.run_from_args(self.args), 0)
            first = self.summary()
            self.assertEqual(request.call_count, 6)
            self.assertEqual(first["counts"]["unknown"], 2)
            self.assertTrue(Path(first["sinks"][0]["llm_path"]).is_file())
            self.assertEqual(pipeline.run_from_args(self.args), 0)
            self.assertNotEqual(first["run_id"], self.summary()["run_id"])
            self.assertEqual(request.call_count, 12)
        for path in Path(self.args.result_path).rglob("*"):
            if path.is_file():
                self.assertNotIn("test-secret", path.read_text())

    def test_single_failure_continues(self):
        with patch.object(llm, "_post_json", side_effect=[ValueError("secret"), self.response(), self.response(), self.response()]):
            self.assertEqual(pipeline.run_from_args(self.args), 1)
        self.assertEqual(self.summary()["status"], "partial")
        self.assertEqual(self.summary()["counts"], {"yes": 0, "no": 0, "unknown": 1, "failed": 1})

    def test_no_sinks_and_static_only_do_not_request(self):
        with patch.object(llm, "_post_json") as request:
            self.detector.run_detection.return_value = []
            self.assertEqual(pipeline.run_from_args(self.args), 0)
            self.assertEqual(self.summary()["sink_count"], 0)
            self.detector.run_detection.return_value = [1]
            self.args.skip_llm = True
            self.assertEqual(pipeline.run_from_args(self.args), 0)
            self.assertEqual(self.summary()["status"], "static_only")
            request.assert_not_called()

    def test_invalid_verdict_is_failure(self):
        with patch.object(llm, "_post_json", return_value=self.response("maybe")):
            self.assertEqual(pipeline.run_from_args(self.args), 1)
        self.assertEqual(self.summary()["counts"]["failed"], 2)

    def test_static_failure_is_saved(self):
        self.detector.run_detection.side_effect = RuntimeError("failure")
        self.assertEqual(pipeline.run_from_args(self.args), 1)
        self.assertEqual(self.summary()["status"], "failed")

    def test_missing_token_fails_before_detection(self):
        with patch.dict("os.environ", {"MANGO_LLM_API_TOKEN": ""}), patch.object(llm, "DEFAULT_API_TOKEN", ""):
            self.assertEqual(pipeline.run_from_args(self.args), 1)
        self.detector.run_detection.assert_not_called()

    def test_configuration_precedence(self):
        self.args.llm_model = "cli-model"
        with patch.dict("os.environ", {"MANGO_LLM_MODEL": "env-model"}), patch.object(llm, "_post_json", return_value=self.response()) as request:
            pipeline.run_from_args(self.args)
            self.assertEqual(request.call_args.args[1]["model"], "cli-model")
            self.args.llm_model = None
            pipeline.run_from_args(self.args)
            self.assertEqual(request.call_args.args[1]["model"], "env-model")


class EntryTests(unittest.TestCase):
    def test_actual_mango_parser_and_dispatch_without_angr(self):
        # Execute the real CLI functions, omitting analysis imports requiring angr.
        directory = Path(pipeline.__file__).parent
        base = ast.parse((directory / "base.py").read_text(encoding="utf-8"))
        mango = ast.parse((directory / "mango.py").read_text(encoding="utf-8"))
        nodes = [n for n in base.body if isinstance(n, ast.FunctionDef) and n.name == "default_parser"]
        nodes += [n for n in mango.body if isinstance(n, ast.FunctionDef) and n.name in {"get_cli_args", "main"}]
        analysis = Mock()
        scope = {"argparse": argparse, "Path": Path, "VULN_TYPES": {"cmdi": []}, "MangoAnalysis": analysis}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "mango_cli", "exec"), scope)
        with patch.object(pipeline, "run_from_args", return_value=0) as run:
            scope["main"](["binary", "-c", "intoverflow", "--skip-llm"])
            run.assert_called_once()
            analysis.assert_not_called()
        scope["main"](["binary", "-c", "cmdi"])
        analysis.return_value.analyze.assert_called_once()
        self.assertFalse(set(analysis.call_args.kwargs) & set(pipeline.OPTION_DESTS))
        for argv in (["binary", "-c", "cmdi", "--skip-llm"],
                     ["binary", "-c", "intoverflow", "--sink", "system"]):
            with self.assertRaises(SystemExit):
                scope["get_cli_args"](argv)


if __name__ == "__main__":
    unittest.main()
