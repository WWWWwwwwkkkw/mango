"""Syntax/readability checks only; does not install uv or run tests in the user's VM."""
import ast
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile

root = Path(__file__).resolve().parent
kit = root/'mango-vm-kit'
rows = []
for path in sorted(kit.glob('*.py')):
    ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    rows.append({'file':path.name,'check':'Python AST parse','passed':True})
readme = (kit/'README_完整步骤.md').read_text(encoding='utf-8')
blocks = re.findall(r'```bash\n(.*?)```', readme, flags=re.S)
commands = root/'guide_commands.syntax.sh'
commands.write_bytes('\n\n'.join(blocks).encode('utf-8'))
checks = [*kit.glob('*.sh'), commands]
for path in sorted(checks):
    linux_path = '/mnt/c/' + path.as_posix()[3:]
    result = subprocess.run(['wsl.exe','-d','Ubuntu','--','bash','-n',linux_path], capture_output=True,text=True)
    rows.append({'file':path.name,'check':'bash -n','passed':result.returncode==0,'stderr':result.stderr,'stdout':result.stdout})
    if result.returncode:
        raise RuntimeError(rows[-1])
with tarfile.open(kit/'mango_0_source.tar.gz') as archive:
    names = archive.getnames()
    for needed in ['mango_0/pyproject.toml','mango_0/README.md',
                   'mango_0/package/argument_resolver/analysis/mango.py',
                   'mango_0/package/argument_resolver/analysis/integer_overflow.py']:
        assert needed in names, needed
    assert not any('__pycache__' in name or name.endswith('.pyc') or '.egg-info/' in name for name in names)
    analyzer=archive.extractfile('mango_0/package/argument_resolver/utils/llm_overflow_analyzer.py').read().decode('utf-8')
    token_assignments=[node for node in ast.parse(analyzer).body if isinstance(node,ast.Assign)
                       and any(isinstance(item,ast.Name) and item.id=='DEFAULT_API_TOKEN' for item in node.targets)]
    assert len(token_assignments)==1 and isinstance(token_assignments[0].value,ast.Constant) and token_assignments[0].value.value in {'', 'xxx'}
rows.append({'file':'mango_0_source.tar.gz','check':'source archive structure','passed':True,'members':len(names)})
(root/'validation.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
print(json.dumps(rows,indent=2))
