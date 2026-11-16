"""Run all fixture static pipelines and record which target functions survive."""
import contextlib
import json
import logging
from pathlib import Path
import sys

root = Path('/root/mango_0')
sys.path.insert(0, str(root / 'package'))
from argument_resolver.utils.integer_overflow_detection import run_detection, save_sink_reports

logging.basicConfig(level=logging.ERROR)
output = root / 'repair_results/static_regression'
output.mkdir(parents=True, exist_ok=True)
cases = json.loads((root / 'samples/httpd_firmware/manifest.json').read_text())
rows = []
for case in cases:
    name = case['binary']
    with (output / f'{name}.log').open('w') as log:
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            try:
                reports = run_detection(str(root / 'samples/httpd_firmware/bin' / name))
                save_sink_reports(reports, str(output / name))
                targets = [hex(r.sink.ins_addr) for r in reports if r.sink.function == case['target_function']]
                row = dict(binary=name, status='complete', sink_count=len(reports), target_addresses=targets,
                           expected_cwe190=case['expected_cwe190'])
            except Exception as exc:
                row = dict(binary=name, status='failed', error=type(exc).__name__)
    rows.append(row)
    print(json.dumps(row), flush=True)
(output / 'summary.json').write_text(json.dumps(rows, indent=2))
assert all(r['status'] == 'complete' for r in rows), rows
assert all(r['target_addresses'] for r in rows if r.get('expected_cwe190')), rows
