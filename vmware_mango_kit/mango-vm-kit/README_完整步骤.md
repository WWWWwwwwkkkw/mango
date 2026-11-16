# VMware Ubuntu：uv + Python 3.11 + Mango 完整测试步骤

不需要卸载系统 Python 3.10。保留它供 Ubuntu 使用，通过 uv 下载独立的 CPython 3.11，再分别建立官方原版、整数溢出扩展版两个虚拟环境。

以下命令面向 Ubuntu 22.04/24.04 x86_64、Bash。全部在 VMware 虚拟机的 Ubuntu 终端中执行。只有 apt 使用 sudo，uv 和 Python 包使用当前普通用户安装；如果你本来就是 root，HOME 会自动对应 /root。

建议本次测试分配 4 个 vCPU、8 GB 内存（条件允许可用 12 GB）和至少 20 GB 空闲磁盘。这是根据此前目标分析资源占用给出的测试建议，不是 Mango 官方最低配置。项目、虚拟环境和结果放在虚拟机自身的 Linux 文件系统中。

官方 Mango 的 Dockerfile 使用 Ubuntu 22.04 + Python 3.11，项目固定 angr 9.2.94。此清单额外固定 pycparser 2.22，因为本次已确认自动选择的 3.x 与该 angr 版本启动不兼容。

## 0. 把测试包放进虚拟机

将本地提供的 `mango-vm-kit.zip` 通过拖拽、共享文件夹或 SCP 复制到虚拟机的 `~/Downloads/mango-vm-kit.zip`。

测试包包含：同一份 httpd、当前扩展版运行源码、此前两套新环境使用的非项目依赖锁、纯 Python 最小复现、独立 CFG 探针和日志脚本。扩展源码不含旧虚拟环境、缓存、历史结果，也不依赖原 WSL 的 /root 路径。

导出副本中的硬编码 LLM API 令牌已清空，原项目文件未改动；本清单使用 --skip-llm，因此不影响此次静态测试。若之后启用 LLM，需要另外配置令牌。

本清单假设 `~/mango-vm-test` 是本次新目录。如已有同名实验，请改用一个新目录名，并在后面的 MANGO_VM_ROOT 中保持一致，不要覆盖已有结果。

## 1. 检查虚拟机和安装系统工具

```bash
cat /etc/os-release
uname -m
python3 --version
free -h
df -h "$HOME"

sudo apt-get update
sudo apt-get install -y \
  curl ca-certificates git build-essential pkg-config \
  libffi-dev libssl-dev libgomp1 graphviz \
  file unzip xz-utils time
```

`uname -m` 应为 `x86_64`。这里不安装或切换系统默认 Python。

## 2. 安装 uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv --version
```

后续都使用 `uv pip` 管理包，并明确指定目标虚拟环境。不要把 uv 的 `--system` 用在这些安装命令上。

## 3. 解压测试包，建立目录

```bash
export MANGO_VM_ROOT="$HOME/mango-vm-test"
mkdir -p "$MANGO_VM_ROOT"
unzip "$HOME/Downloads/mango-vm-kit.zip" -d "$MANGO_VM_ROOT"
export MANGO_KIT="$MANGO_VM_ROOT/mango-vm-kit"
mkdir -p "$MANGO_VM_ROOT/results"

(cd "$MANGO_KIT" && sha256sum -c SHA256SUMS)
file "$MANGO_KIT/httpd"
sha256sum "$MANGO_KIT/httpd"
```

SHA256SUMS 应全部为 OK。httpd 的 SHA256 应为：

```text
5c6330ab898620f25009d1dc5fa4046e2ca7c3beacf3cdbbf9b12a4e028b5661
```

文件应识别为 MIPS 小端 ELF。这里分析二进制，不直接执行 httpd，所以不需要把 MIPS httpd 当作 x86 程序运行。

## 4. 用 uv 下载独立 Python 3.11

```bash
uv python install 3.11
uv python list --only-installed
export MANGO_PY311="$(uv python find --managed-python 3.11)"

printf 'uv Python: %s\n' "$MANGO_PY311"
"$MANGO_PY311" -VV
"$MANGO_PY311" -I -S -c 'import sys; print("executable:",sys.executable); print("base_prefix:",sys.base_prefix)'
python3 --version

uv --version > "$MANGO_VM_ROOT/results/uv-version.txt"
"$MANGO_PY311" -VV > "$MANGO_VM_ROOT/results/python-version.txt" 2>&1
```

`MANGO_PY311` 通常位于当前用户的 uv Python 管理目录中，应指向 uv 下载的 3.11，而非系统 `/usr/bin/python3.10`。uv 默认安装版本化入口；这里没有要求它把系统 python3 切换为 3.11。具体补丁版本以 `-VV` 记录为准。

保存后续步骤用的路径：

```bash
cat > "$MANGO_VM_ROOT/settings.sh" <<'EOF'
export PATH="$HOME/.local/bin:$PATH"
export MANGO_VM_ROOT="${MANGO_VM_ROOT:-$HOME/mango-vm-test}"
export MANGO_KIT="$MANGO_VM_ROOT/mango-vm-kit"
export MANGO_OFF_SRC="$MANGO_VM_ROOT/operation-mango-public"
export MANGO_EXT_SRC="$MANGO_VM_ROOT/mango_0"
export MANGO_OFF_ENV="$MANGO_VM_ROOT/.venv-official"
export MANGO_EXT_ENV="$MANGO_VM_ROOT/.venv-extended"
export MANGO_TARGET="$MANGO_KIT/httpd"
export MANGO_PY311="$(uv python find --managed-python 3.11)"
unset PYTHONPATH PYTHONHOME
EOF

source "$MANGO_VM_ROOT/settings.sh"
```

若关闭终端，重新执行：

```bash
export MANGO_VM_ROOT="$HOME/mango-vm-test"
source "$MANGO_VM_ROOT/settings.sh"
```

若你选了自定义目录，请将上面的路径也改成同一个目录。

## 5. 先验证纯 Python，暂不安装 Mango

```bash
bash "$MANGO_KIT/runtime_suite.sh" "$MANGO_PY311" 20
```

该脚本只用标准库，不读取固件、不导入 Mango/angr/CFFI/PyVEX；每次使用 `-I -S -B`，隔离环境变量/用户包并跳过 site 初始化。预期为 20 次 exit 0、Failures 0/20。这个结果只是最小复现通过，不保证所有程序稳定。

若出现段错误、不合理的 TypeError/SystemError，先保留该目录日志；这时已有不依赖 Mango 的故障证据。后续测试即使继续，也不能把所有异常都归因于扩展代码。

## 6. 创建官方原版环境

先克隆与本次 WSL 对照相同提交：

```bash
git clone https://github.com/sefcom/operation-mango-public.git "$MANGO_OFF_SRC"
git -C "$MANGO_OFF_SRC" checkout --detach 85034001d7ce365de5c3520e486ac5ed7adf0bc3
git -C "$MANGO_OFF_SRC" rev-parse HEAD \
  > "$MANGO_VM_ROOT/results/official-commit.txt"

uv venv --python "$MANGO_PY311" "$MANGO_OFF_ENV"

uv pip install --python "$MANGO_OFF_ENV/bin/python" \
  -r "$MANGO_KIT/requirements-baseline.lock"

uv pip install --python "$MANGO_OFF_ENV/bin/python" \
  --no-deps --no-build-isolation "$MANGO_OFF_SRC"

uv pip check --python "$MANGO_OFF_ENV/bin/python"
"$MANGO_OFF_ENV/bin/python" -X faulthandler -m pip check
uv pip freeze --python "$MANGO_OFF_ENV/bin/python" \
  > "$MANGO_VM_ROOT/results/official-freeze.txt"

"$MANGO_OFF_ENV/bin/mango" --help
"$MANGO_OFF_ENV/bin/env_resolve" --help
"$MANGO_OFF_ENV/bin/python" -c 'import sys,angr,pyvex,pycparser; import argument_resolver.analysis.mango as m; print(sys.executable); print(angr.__version__,pyvex.__version__,pycparser.__version__); print(m.__file__)'
```

依赖锁包含 pip、setuptools、wheel，因此 uv venv 创建时没有 pip 也不影响安装；uv 自己不依赖该环境内的 pip。项目安装使用非 editable 模式，后续修改源码后需要重装该包。

主要预期版本：angr/PyVEX 9.2.94、CFFI 2.1.1、pycparser 2.22。其余版本由包内锁文件固定，不会自动解析为另一套最新依赖。

## 7. 测官方小样本

```bash
bash "$MANGO_KIT/run_mango.sh" \
  official_simple "$MANGO_OFF_ENV" \
  "$MANGO_OFF_SRC/package/tests/binaries/simple/program" \
  cmdi --disable-progress
```

预期 exit 0，并生成 `results/cmdi_results.json`，其 error 为 null。若这一步失败，先检查打印出来的日志目录。

## 8. 独立 CFG 测试与官方完整 cmdi

先重复 3 次底层 CFG 测试：

```bash
bash "$MANGO_KIT/cfg_suite.sh" \
  official "$MANGO_OFF_ENV" "$MANGO_TARGET" 3
```

每次预期 exit 0，日志末尾含 `"cfg_passed": true`。该探针独立调用 angr，不走 Mango CLI；通过它不等于完整 Mango 分析已通过。

再运行官方完整命令注入分析：

```bash
bash "$MANGO_KIT/run_mango.sh" \
  official_cmdi "$MANGO_OFF_ENV" "$MANGO_TARGET" \
  cmdi --disable-progress
```

辅助脚本等价于运行该虚拟环境内的 mango，额外自动指定独立结果目录、开启 faulthandler、记录 GNU time 资源统计与真实退出码。默认单次最多 20 分钟。测试过程中输出写入日志，另一个终端可用下面命令查看文件位置：

```bash
export MANGO_VM_ROOT="$HOME/mango-vm-test"
source "$MANGO_VM_ROOT/settings.sh"
find "$MANGO_VM_ROOT/results" -name console.log -print
```

选择打印出的某个 console.log，再执行 `tail -f "该文件的完整路径"`。Ctrl+C 结束 tail 不会停止后台测试终端中的 Mango。

若使用了自定义实验目录，新终端中的 MANGO_VM_ROOT 也应改为该路径。

如果要允许单次运行 40 分钟，可在本终端设置后再运行测试：

```bash
export MANGO_TIMEOUT=40m
```

## 9. 配置扩展版独立环境

```bash
tar -xzf "$MANGO_KIT/mango_0_source.tar.gz" -C "$MANGO_VM_ROOT"
test -f "$MANGO_EXT_SRC/pyproject.toml"

uv venv --python "$MANGO_PY311" "$MANGO_EXT_ENV"

uv pip install --python "$MANGO_EXT_ENV/bin/python" \
  -r "$MANGO_KIT/requirements-baseline.lock"

uv pip install --python "$MANGO_EXT_ENV/bin/python" \
  --no-deps --no-build-isolation "$MANGO_EXT_SRC"

uv pip check --python "$MANGO_EXT_ENV/bin/python"
"$MANGO_EXT_ENV/bin/python" -X faulthandler -m pip check
uv pip freeze --python "$MANGO_EXT_ENV/bin/python" \
  > "$MANGO_VM_ROOT/results/extended-freeze.txt"

"$MANGO_EXT_ENV/bin/mango" --help
"$MANGO_EXT_ENV/bin/python" -c 'import sys,angr,pyvex,pycparser; import argument_resolver.analysis.mango as m; print(sys.executable); print(angr.__version__,pyvex.__version__,pycparser.__version__); print(m.__file__)'
```

扩展版帮助应包含 `intoverflow` 和 `--skip-llm`。原版帮助不包含这两个功能，这是正常的版本区别。

## 10. 测扩展版 CFG、cmdi 和 intoverflow

```bash
bash "$MANGO_KIT/cfg_suite.sh" \
  extended "$MANGO_EXT_ENV" "$MANGO_TARGET" 3

bash "$MANGO_KIT/run_mango.sh" \
  extended_cmdi "$MANGO_EXT_ENV" "$MANGO_TARGET" \
  cmdi --disable-progress

bash "$MANGO_KIT/run_mango.sh" \
  extended_intoverflow "$MANGO_EXT_ENV" "$MANGO_TARGET" \
  intoverflow --skip-llm
```

intoverflow 本次只测静态流程，按之前的选择不调用 LLM。不要给该分类增加 `--disable-progress`，扩展 CLI 会拒绝这个参数并返回 2。两个完整测试需要在前一个命令结束后再执行下一个，不并发运行。

## 11. 原版/扩展版 CMDI 交替复测

首次测试完成后，用相同目标再交替复测两轮，观察是否间歇性失败：

```bash
for trial in 1 2; do
  bash "$MANGO_KIT/run_mango.sh" \
    "official_cmdi_repeat_$trial" "$MANGO_OFF_ENV" "$MANGO_TARGET" \
    cmdi --disable-progress

  bash "$MANGO_KIT/run_mango.sh" \
    "extended_cmdi_repeat_$trial" "$MANGO_EXT_ENV" "$MANGO_TARGET" \
    cmdi --disable-progress
done
```

如需复测整数溢出静态流程：

```bash
bash "$MANGO_KIT/run_mango.sh" \
  extended_intoverflow_repeat "$MANGO_EXT_ENV" "$MANGO_TARGET" \
  intoverflow --skip-llm
```

不要仅根据一次原版通过和一次扩展版失败就判定扩展改变了 CMDI。

## 12. 读取和打包结果

```bash
"$MANGO_PY311" -I -S "$MANGO_KIT/summarize_results.py" \
  "$MANGO_VM_ROOT/results"

find "$MANGO_VM_ROOT/results" -name exit_code.txt -print -exec cat {} \;

tar -czf "$HOME/mango-vm-results-$(date +%Y%m%d-%H%M%S).tar.gz" \
  -C "$MANGO_VM_ROOT" results settings.sh
```

测试脚本会为每次 Mango 运行分别保存 `command.txt`、`console.log`、`resources.txt`、`exit_code.txt` 和结果目录。`summary.csv` 由汇总命令生成。

| 观察值 | 含义 |
| --- | --- |
| exit 0 | 进程正常返回；仍检查结果 JSON 的 error/status |
| exit 1 | 未处理异常或分析失败，看调用栈 |
| exit 2 | 参数或用法错误，通常尚未开始分析 |
| exit 124 | 本清单设置的运行时限到达，不是已证实的程序段错误 |
| exit 137 | 进程收到 SIGKILL，可能是强制超时或 OOM 等，需结合日志判断 |
| exit 139 | SIGSEGV 段错误 |
| cmdi_results.json 的 error=null | 单独这一字段不能证明运行完整；Mango 会写中间结果 |
| intoverflow 的 status=static_only 且 exit 0 | 静态流程完整结束，LLM 被跳过；不是确认漏洞结论 |

判断“过 CFG”：独立探针有 cfg_passed=true，或者完整 cmdi 已进入后续 VRA/RDA。完整 cmdi 的 `TARGETING SINKS` 标记表示初始化阶段已完成。整数溢出不保证使用相同日志标记，不能拿该标记缺失认定它一定没过 CFG。

如果发生 137，可另外读取内核线索：

```bash
sudo dmesg -T | tail -n 100
```

## 13. 日常激活方式

上面的命令全都明确指定环境，因此不依赖激活状态。交互使用时任选一个环境激活：

```bash
source "$MANGO_OFF_ENV/bin/activate"
which python
which mango
python --version
deactivate

source "$MANGO_EXT_ENV/bin/activate"
which python
which mango
python --version
deactivate
```

虚拟机与 WSL 如果运行在同一台物理宿主上，仍共用该物理硬件；VMware 的交叉测试有助于区分用户态系统/解释器环境，但不能单独排除宿主硬件因素。

本清单及脚本在当前工作区做语法和内容检查；尚未在你的 VMware 虚拟机执行，实际结果以你运行后生成的日志为准。

## 参考

- [uv 安装](https://docs.astral.sh/uv/getting-started/installation/)
- [uv 管理 Python](https://docs.astral.sh/uv/guides/install-python/)
- [uv 虚拟环境与 --python](https://docs.astral.sh/uv/pip/environments/)
- [uv 命令参考](https://docs.astral.sh/uv/reference/cli/)
- [Mango 原版](https://github.com/sefcom/operation-mango-public)
- [Mango Dockerfile](https://github.com/sefcom/operation-mango-public/blob/master/docker/Dockerfile)
