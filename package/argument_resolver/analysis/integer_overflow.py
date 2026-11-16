"""Mango CLI orchestration for arithmetic sinks and LLM judgments."""

import contextlib
import hashlib
import json
import logging
import os
from pathlib import Path
import sys
import time
import uuid

from argument_resolver.utils import llm_overflow_analyzer as llm
from argument_resolver.utils.overflow_logging import overflow_logging


OPTION_DESTS = (
    "int_bits", "int_ops", "int_limit", "int_no_cross_function", "skip_llm",
    "llm_api_url", "llm_api_token", "llm_model", "llm_timeout",
)


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise ValueError("must be positive")
    return number


def add_cli_arguments(parser):
    group = parser.add_argument_group("Integer overflow", "Options for -c intoverflow")
    group.add_argument("--int-bits", nargs="+", type=int, choices=[8, 16, 32, 64])
    group.add_argument("--int-ops", nargs="+", help="VEX operations, e.g. Add Sub Mul Shl")
    group.add_argument("--int-limit", type=positive_int, help="Candidate limit before width/constant filtering")
    group.add_argument("--int-no-cross-function", action="store_true")
    group.add_argument("--skip-llm", action="store_true", help="Save static reports only")
    group.add_argument("--llm-api-url")
    group.add_argument("--llm-api-token")
    group.add_argument("--llm-model")
    group.add_argument("--llm-timeout", type=positive_int, default=60)


def validate_cli_arguments(parser, args, argv=None):
    tokens = sys.argv[1:] if argv is None else argv
    explicit = {token.split("=", 1)[0] for token in tokens if token.startswith("-")}
    # argparse accepts unique long-option abbreviations; validate their resolved names.
    known_options = parser._option_string_actions
    for option in list(explicit):
        if option.startswith("--") and option not in known_options:
            matches = [name for name in known_options if name.startswith(option)]
            if len(matches) == 1:
                explicit.add(matches[0])
    if args.sink_category != "intoverflow":
        options = {"--" + name.replace("_", "-") for name in OPTION_DESTS}
        if explicit & options:
            parser.error("Integer overflow options require -c intoverflow")
        return
    unsupported = {
        "--sink", "--arg", "--source", "--min-depth", "--exclude", "--workers",
        "--ld-paths", "--rda-timeout", "--full-execution", "--forward-trace",
        "--enable-breakpoint", "--keyword-dict", "--env-dict", "--merge-execve", "--concise",
        "--disable-progress",
    }
    if explicit & unsupported:
        parser.error("Unsupported for intoverflow: " + ", ".join(sorted(explicit & unsupported)))
    if args.max_depth <= 0:
        parser.error("--max-depth must be positive for intoverflow")


class _Tee:
    def __init__(self, console, logfile):
        self.console, self.logfile = console, logfile

    def write(self, text):
        self.console.write(text)
        return self.logfile.write(text)

    def flush(self):
        self.console.flush()
        self.logfile.flush()


def run_from_args(args):
    """Run a binary through both stages; return zero only on full completion."""
    output = Path(args.result_path)
    output.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "_" + uuid.uuid4().hex[:8]
    run_dir = output / "intoverflow" / run_id
    run_dir.mkdir(parents=True)
    api_options = {
        "api_url": args.llm_api_url or os.getenv("MANGO_LLM_API_URL") or llm.DEFAULT_API_URL,
        "api_token": args.llm_api_token or os.getenv("MANGO_LLM_API_TOKEN") or llm.DEFAULT_API_TOKEN,
        "model": args.llm_model or os.getenv("MANGO_LLM_MODEL") or llm.DEFAULT_MODEL,
        "timeout": args.llm_timeout,
    }
    summary = {
        "category": "intoverflow", "path": str(Path(args.bin_path).resolve()),
        "run_id": run_id, "status": "running", "sha256": None,
        "config": {"bits": args.int_bits, "ops": args.int_ops, "limit": args.int_limit,
                   "max_depth": args.max_depth, "cross_function": not args.int_no_cross_function,
                   "skip_llm": args.skip_llm, "model": api_options["model"],
                   "llm_timeout": args.llm_timeout},
        "sink_count": 0, "counts": {"yes": 0, "no": 0, "unknown": 0, "failed": 0},
        "sinks": [], "errors": [], "timings": {},
    }
    started = time.monotonic()
    exit_code = 0
    with (output / "intoverflow_mango.out").open("a", encoding="utf-8") as logfile, overflow_logging(getattr(logging, args.log_level), logfile):
        try:
            with contextlib.redirect_stdout(_Tee(sys.stdout, logfile)), contextlib.redirect_stderr(_Tee(sys.stderr, logfile)):
                print(f"[intoverflow] Run {run_id}: {args.bin_path}")
                binary = Path(args.bin_path)
                digest = hashlib.sha256()
                with binary.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                summary["sha256"] = digest.hexdigest()
                if not args.skip_llm and not api_options["api_token"]:
                    raise ValueError("Missing LLM API token")
                from argument_resolver.utils.integer_overflow_detection import run_detection, save_sink_reports
                logging.getLogger(__name__).info("Static analysis: scanning and tracing arithmetic candidates")
                stage_start = time.monotonic()
                try:
                    reports = run_detection(
                        str(binary), bit_widths=args.int_bits, op_names=args.int_ops,
                        max_depth=args.max_depth, cross_function=not args.int_no_cross_function,
                        limit=args.int_limit,
                    )
                    paths = save_sink_reports(reports, str(run_dir / "sinks"))
                finally:
                    summary["timings"]["static_seconds"] = time.monotonic() - stage_start
                summary["sink_count"] = len(paths)
                logging.getLogger(__name__).info("Static analysis complete: %d sink reports", len(paths))
                stage_start = time.monotonic()
                for index, path in enumerate(paths, 1):
                    payload = json.loads(Path(path).read_text(encoding="utf-8"))
                    entry = {"sink_index": index, "sink_address": payload.get("sink_address"),
                             "sink_function": payload.get("sink_function"), "report_path": str(Path(path).resolve())}
                    summary["sinks"].append(entry)
                    if args.skip_llm:
                        entry["status"] = "skipped"
                        continue
                    print(f"[intoverflow] LLM sink {index}/{len(paths)}")
                    try:
                        verdict = llm.analyze_sink_file(path, str(run_dir / "llm"), **api_options)
                        entry.update(verdict)
                        entry["status"] = "complete"
                        entry["llm_path"] = str((run_dir / "llm" / f"sink_{index}_llm.json").resolve())
                        entry["verdict_path"] = str((run_dir / "llm" / f"sink_{index}_verdict.json").resolve())
                        summary["counts"][verdict["verdict"]] += 1
                    except Exception as exc:
                        # Do not persist exception text: remote errors can echo credentials.
                        entry.update(status="failed", error=type(exc).__name__)
                        summary["counts"]["failed"] += 1
                        print(f"[intoverflow] sink {index} failed ({type(exc).__name__})")
                summary["timings"]["llm_seconds"] = time.monotonic() - stage_start
                failed = summary["counts"]["failed"]
                summary["status"] = (
                    ("failed" if failed == len(paths) else "partial") if failed
                    else ("static_only" if args.skip_llm else "complete")
                )
                exit_code = 1 if failed else 0
        except Exception as exc:
            summary["status"] = "failed"
            summary["errors"].append({"type": type(exc).__name__})
            print(f"[intoverflow] Analysis failed ({type(exc).__name__})", file=sys.stderr)
            exit_code = 1
        finally:
            summary["timings"]["total_seconds"] = time.monotonic() - started
            serialized = json.dumps(summary, indent=2)
            (run_dir / "intoverflow_results.json").write_text(serialized, encoding="utf-8")
            (output / "intoverflow_results.json").write_text(serialized, encoding="utf-8")
    print(f"[intoverflow] {summary['status']}: {output / 'intoverflow_results.json'}")
    return exit_code
