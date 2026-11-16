"""Summarize completed category runs without treating timeouts as passes."""
import json
from pathlib import Path
import re
import sys

root = Path(sys.argv[1]).resolve()
metadata = json.loads((root / 'metadata.json').read_text())
records = json.loads((root / 'summary.json').read_text())
assert len(records) == len(metadata['categories']) == 9
assert {row['category'] for row in records} == set(metadata['categories'])
lines = [
    '# AC12 httpd：其他 -c 分类对照测试', '',
    '同一目标、同一 WSL Ubuntu、同一 `/root/myenv`，未修改分析器或依赖。', '',
    f"- 实际入口：`{metadata['mango_source']}`",
    f"- Python：`{metadata['python'].splitlines()[0]}`；angr：`{metadata['angr']}`。",
    f"- 目标 SHA256：`{metadata['target_sha256']}`。",
    '- 每类独立启动一次，独立结果目录；按顺序运行。每类上限 180 秒。',
    '- 命令仅额外启用 faulthandler、关闭进度条并指定结果目录；未缩减分析范围。', '',
    '| 分类 | 退出码 | 秒 | 观察结果 | 中断阶段 |',
    '| --- | ---: | ---: | --- | --- |',
]
details = []
for row in records:
    category_dir = root / row['category']
    saved = json.loads((category_dir / 'exit.json').read_text())
    assert saved == row
    content = (category_dir / 'console.log').read_text(errors='replace')
    exceptions = re.findall(r'^[\w.]*(?:Error|Exception):[^\n]*', content, re.M)
    leaf = exceptions[-1].strip() if exceptions else ''
    outcome = '超时，未证实完成' if row['timed_out'] else (
        'SIGSEGV 段错误' if row['segfault'] else ('正常返回' if row['exit_code'] == 0 else leaf or '异常退出'))
    row['observed_error'] = outcome
    row['observed_stage'] = row['stage_from_trace']
    if row['observed_stage'] == 'unknown' and ('cle/backends/elf/' in content or 'elftools/' in content):
        row['observed_stage'] = 'ELF 加载/解析'
    lines.append(f"| `{row['category']}` | {row['exit_code']} | {row['seconds']:.2f} | {outcome.replace('|', '/')} | {row['observed_stage']} |")
    details.append(row)
lines += [
    '', '## 如何解释', '',
    f"本轮共 {len(records)} 类：{sum(row['segfault'] for row in records)} 类段错误、{sum(row['exit_code'] != 0 and not row['segfault'] and not row['timed_out'] for row in records)} 类其他异常退出、{sum(row['timed_out'] for row in records)} 类超时；没有一个分类正常完成。所有分类均未产生结果 JSON。", '',
    '退出码 1 表示未处理异常导致失败；139 表示本次通过 GNU time 启动的子进程收到了 SIGSEGV。两者需分别记录，不能把所有失败都称为段错误。', '',
    '非 intoverflow 分类共用 `ScriptBase.init_analysis()` 中的 CFGFast 初始化；CFG 构建在加载分类对应的 sinks 之前执行。若在此处失败，尚未进入该分类的专用检测逻辑。', '',
    '本轮结果只能证明相同环境、同一固件下的这些执行是否失败及失败位置。单次试验不能给出各分类的崩溃概率，也不能证明所有异常的精确底层原因完全相同。', '',
    '失败或超时的分析不能用来判断固件没有漏洞。', '',
    '## 复现', '', '```bash', 'cd /root/mango_0', 'source /root/myenv/bin/activate',
    'unset PYTHONPATH', 'export PYTHONFAULTHANDLER=1',
    'mango /root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd \\',
    '  -c cmdi --disable-progress --results /root/mango_0/repair_results/ac12_cmdi_reproduce', '```', '',
    '将 `cmdi` 换成表中的其他分类即可。复现时使用新的结果目录。', '',
    '## 原始证据', '',
    '当前目录中的 `metadata.json`、`summary.json` 记录环境和每类命令；每个分类子目录分别包含 `console.log`、`exit.json`、`resources.txt`。', '',
]
(root / '其他分类测试结果.md').write_text('\n'.join(lines), encoding='utf-8')
(root / 'verified_summary.json').write_text(json.dumps(details, indent=2, ensure_ascii=False), encoding='utf-8')
for row in details:
    print(f"{row['category']:8} exit={row['exit_code']:3} seconds={row['seconds']:7.2f} {row['observed_error']}")
print('REPORT ' + str(root / '其他分类测试结果.md'))
