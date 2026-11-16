"""Clear a hard-coded API credential in the exported test copy, never the source project."""
import ast
import io
import json
from pathlib import Path
import tarfile

root = Path(__file__).resolve().parent
archive = root/'mango-vm-kit/mango_0_source.tar.gz'
temporary = root/'mango-vm-kit/mango_0_source.sanitized.tar.gz'
target = 'mango_0/package/argument_resolver/utils/llm_overflow_analyzer.py'
sanitized = False
with tarfile.open(archive,'r:gz') as source, tarfile.open(temporary,'w:gz') as destination:
    for member in source.getmembers():
        if not member.isfile():
            destination.addfile(member)
            continue
        payload = source.extractfile(member).read()
        if member.name == target:
            text = payload.decode('utf-8')
            lines = text.splitlines(keepends=True)
            nodes = [node for node in ast.parse(text).body if isinstance(node,ast.Assign)
                     and any(isinstance(item,ast.Name) and item.id=='DEFAULT_API_TOKEN' for item in node.targets)]
            assert len(nodes)==1
            node=nodes[0]
            lines[node.lineno-1:node.end_lineno] = ['DEFAULT_API_TOKEN = ""  # Cleared in exported static-test copy.\n']
            text=''.join(lines)
            check=[node for node in ast.parse(text).body if isinstance(node,ast.Assign)
                   and any(isinstance(item,ast.Name) and item.id=='DEFAULT_API_TOKEN' for item in node.targets)][0]
            assert isinstance(check.value,ast.Constant) and check.value.value==''
            payload=text.encode('utf-8')
            member.size=len(payload)
            sanitized=True
        destination.addfile(member,io.BytesIO(payload))
assert sanitized
temporary.replace(archive)
(root/'mango-vm-kit/export_notes.json').write_text(json.dumps({
    'source_project_modified':False,'exported_copy_changes':[{
        'file':target,'change':'DEFAULT_API_TOKEN cleared; static analysis behavior retained',
        'reason':'The requested tests explicitly use --skip-llm.'}]},indent=2))
print('Exported static-test copy sanitized; original project unchanged.')
