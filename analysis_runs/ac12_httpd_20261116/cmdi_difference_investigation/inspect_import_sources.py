import ast
import difflib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
official = Path('/root/myenv_mango_official/lib/python3.11/site-packages/argument_resolver')
extended = Path('/root/myenv_mango_extended/lib/python3.11/site-packages/argument_resolver')
path = 'utils/call_trace.py'
diff = ''.join(difflib.unified_diff((official/path).read_text().splitlines(keepends=True), (extended/path).read_text().splitlines(keepends=True),
                                  fromfile='official/'+path,tofile='extended/'+path))
(root/'call_trace.diff').write_text(diff)
print(diff)
rows = []
for path in sorted(extended.rglob('*.py')):
    if path.name not in ['integer_overflow.py','integer_overflow_detection.py','overflow_logging.py','test_trace.py','llm_overflow_analyzer.py','vex_helpers.py','width_screening.py','arithmetic_operand_origin.py']:
        continue
    tree = ast.parse(path.read_text())
    imports = []
    calls = []
    for node in tree.body:
        if isinstance(node, (ast.Import,ast.ImportFrom)):
            imports.append(ast.unparse(node))
        elif not isinstance(node, (ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
            for child in ast.walk(node):
                if isinstance(child,ast.Call):
                    calls.append({'line':child.lineno, 'call':ast.unparse(child.func)})
    rows.append({'file':str(path.relative_to(extended)),'imports':imports,'top_level_calls':calls})
(root/'extension_import_source_summary.json').write_text(json.dumps(rows,indent=2))
print(json.dumps(rows,indent=2))
