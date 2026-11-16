"""Combine the completed retry with original results, with explicit provenance."""
import json
from pathlib import Path

base = Path('/root/mango_0/repair_results/cedar')
original = base / 'intoverflow_results.json'
retry_dir = base / 'retry/20260920T005032'
report = json.loads(original.read_text())
report['original_summary'] = str(original)
report['original_status'] = report['status']
report['verification_note'] = 'Combined original successful results with separately completed retries; timings describe original run only.'
for entry in report['sinks']:
    if entry['status'] != 'failed':
        continue
    path = retry_dir / f"sink_{entry['sink_index']}_verdict.json"
    verdict = json.loads(path.read_text())
    entry['original_error'] = entry.pop('error')
    entry.update(verdict)
    entry['status'] = 'complete'
    entry['retried'] = True
    entry['verdict_path'] = str(path)
    entry['llm_path'] = str(retry_dir / f"sink_{entry['sink_index']}_llm.json")
report['counts'] = {key: sum(s.get('verdict') == key for s in report['sinks']) for key in ('yes', 'no', 'unknown')}
report['counts']['failed'] = sum(s['status'] == 'failed' for s in report['sinks'])
report['status'] = 'complete_after_retry'
out = base / 'repair_verified_results.json'
out.write_text(json.dumps(report, indent=2))
print(out)
print(json.dumps(report['counts']))
