"""Apply only the reviewed changes to the user's WSL checkout, preserving configuration."""
from pathlib import Path
import shutil
import time

local = Path(__file__).resolve().parents[2]
target = Path('/root/mango_0')
changes = {
    'integer_overflow.py': [
        ('self._handle_expr(expr.addr, ExprContext("load_addr", ctx.stmt_idx, ctx.produced_tmp, ctx.target_reg))',
         'self._handle_expr(expr.addr, ExprContext("load_addr", ctx.stmt_idx))'),
        ('elif use.kind == "arith":', 'elif use.kind in ("arith", "tmp_assign"):'),
        ('if use.kind == "arith" and use.produced_tmp is not None:',
         'if use.kind in ("arith", "tmp_assign") and use.produced_tmp is not None:'),
        ('        if flags["used_as_store_value"]:\n            return "value_arith"\n        if flags["updates_pc"]:\n            return "control_flow"\n        if flags["updates_sp"]:\n            return "stack_update"',
         '        if flags["updates_pc"]:\n            return "control_flow"\n        if flags["updates_sp"]:\n            return "stack_update"\n        if flags["used_as_store_value"]:\n            return "value_arith"'),
    ],
}
backup = target / '.repair_backups' / time.strftime('%Y%m%dT%H%M%S')
backup.mkdir(parents=True, exist_ok=True)
for name, replacements in changes.items():
    path = target / 'package/argument_resolver/utils' / name
    text = path.read_text()
    for old, new in replacements:
        if old not in text:
            if new in text:
                continue
            raise RuntimeError(f'Unexpected source in {name}')
        text = text.replace(old, new)
    shutil.copy2(path, backup / name)
    path.write_text(text)
name = 'llm_overflow_analyzer.py'
path = target / 'package/argument_resolver/utils' / name
text = path.read_text()
source = (local / 'package/argument_resolver/utils' / name).read_text()
start = source.index('        f"Immutable target:')
end = source.index('        "Previous JSON (paste exactly):', start)
anchor = '        "Previous JSON (paste exactly):'
if '        f"Immutable target:' not in text:
    assert text.count(anchor) == 1
    shutil.copy2(path, backup / name)
    path.write_text(text.replace(anchor, source[start:end] + anchor))
print('Applied targeted fixes; original files backed up to', backup)
trace = target / 'package/argument_resolver/utils/test_trace.py'
shutil.copy2(trace, backup / 'test_trace.py')
shutil.copy2(local / 'package/argument_resolver/utils/test_trace.py', trace)
