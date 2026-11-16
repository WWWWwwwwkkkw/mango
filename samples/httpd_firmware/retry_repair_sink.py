"""Retry failed repair-run reports, preserving the original summary."""
import json
import logging
import os
from pathlib import Path
import sys
import time

root = Path('/root/mango_0')
sys.path.insert(0, str(root / 'package'))
from argument_resolver.utils import llm_overflow_analyzer as llm

logging.basicConfig(level=logging.INFO)
base = root / 'repair_results/cedar'
summary = json.loads((base / 'intoverflow_results.json').read_text())
out = base / 'retry' / time.strftime('%Y%m%dT%H%M%S')
out.mkdir(parents=True)
results = []
for entry in summary['sinks']:
    if entry['status'] != 'failed':
        continue
    try:
        result = llm.analyze_sink_file(
            entry['report_path'], str(out),
            api_url=os.getenv('MANGO_LLM_API_URL') or llm.DEFAULT_API_URL,
            api_token=os.getenv('MANGO_LLM_API_TOKEN') or llm.DEFAULT_API_TOKEN,
            model=os.getenv('MANGO_LLM_MODEL') or llm.DEFAULT_MODEL, timeout=180)
        results.append(dict(result, status='complete'))
        print(json.dumps(results[-1]), flush=True)
    except Exception as exc:
        results.append(dict(sink_index=entry['sink_index'], status='failed', error=type(exc).__name__))
        print(json.dumps(results[-1]), flush=True)
(out / 'retry_summary.json').write_text(json.dumps(results, indent=2))
print('Retry results:', out, flush=True)
