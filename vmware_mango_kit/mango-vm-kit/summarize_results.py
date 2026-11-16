"""Print logged Mango process exits; a partial JSON is never treated as success."""
import csv
import json
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
rows = []
for exit_file in sorted(root.rglob('exit_code.txt')):
    directory = exit_file.parent
    code = int(exit_file.read_text().strip())
    content = (directory/'console.log').read_text(errors='replace') if (directory/'console.log').is_file() else ''
    json_path = directory/'results/intoverflow_results.json'
    if not json_path.is_file():
        json_path = directory/'results/cmdi_results.json'
    parse_error = ''
    try:
        data = json.loads(json_path.read_text()) if json_path.is_file() else {}
    except (ValueError, OSError) as error:
        data = {}
        parse_error = str(error)
    row = {'run':directory.name,'exit_code':code,'result_status':data.get('status',''),
           'result_error':str(data.get('error','')),'result_json':str(json_path) if json_path.is_file() else '',
           'cfg_and_vra_marker':'TARGETING SINKS:' in content,'json_parse_error':parse_error,
           'log':str(directory/'console.log')}
    rows.append(row)
    print(json.dumps(row,ensure_ascii=False))
if rows:
    with (root/'summary.csv').open('w',newline='') as handle:
        writer=csv.DictWriter(handle,fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print('SUMMARY',root/'summary.csv')
