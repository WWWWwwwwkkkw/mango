# 模拟固件 HTTP 服务：整数溢出基准集

10 个虚构设备固件样本，3 个含 CWE-190，7 个目标路径有保护。
名称不对应真实厂商、产品或 CVE。它们是小型、可审计的 HTTP 请求处理模拟程序，
不是完整固件或生产 HTTP 守护进程。每个程序读取标准输入中的一个 HTTP 请求，
类似 inetd 启动的服务，处理管理 API 后退出，不监听网络。

固件 Web 服务常包含管理页面、路由分发、CGI、升级上传、配置导入和日志/录像导出。
本集合模拟其中的暂存空间预留接口。常见整数溢出风险是先将长度相加或将数量与
单项大小相乘，再用已回绕的结果检查配额、分配缓冲区。参考：

- https://openwrt.org/docs/guide-user/services/webserver/uhttpd
- https://git.openwrt.org/openwrt/openwrt/tree/?path=package%2Fnetwork%2Fservices%2Fuhttpd%2FMakefile
- https://cwe.mitre.org/data/definitions/190

## 样本与预期

| 二进制 | 模拟设备 / API | CWE-190 | 运算与保护 |
|---|---|---|---|
| cedar_router_httpd | 路由器升级 /upload | 有 | chunk_count × chunk_bytes，乘法后才检查配额 |
| harbor_nas_httpd | NAS 配置恢复 /restore | 有 | config_bytes + index_bytes，加法后才检查配额 |
| meadow_nvr_httpd | NVR 录像导出 /export | 有 | frame_count × frame_bytes，只限制帧大小 |
| birch_gateway_httpd | 网关升级 /upload | 无（目标路径） | 乘法前检查 UINT32_MAX / b |
| coral_ap_httpd | AP 配置恢复 /restore | 无（目标路径） | 加法前检查 UINT32_MAX - b |
| willow_camera_httpd | 摄像头快照 /snapshot | 无（目标路径） | 两操作数独立上限 |
| slate_switch_httpd | 交换机备份 /backup | 无（目标路径） | uint64 加法、校验后转 uint32 |
| amber_mesh_httpd | Mesh 节点表 /peers | 无（目标路径） | uint64 乘法、校验后转 uint32 |
| brook_sensor_httpd | 传感器历史记录 /history | 无（目标路径） | 移位前检查位数和高位 |
| spruce_hub_httpd | 中心节点配置包 /bundle | 无（目标路径） | 两长度独立上限 |

所有业务路由前缀为 `/api`；另有 `/status`。参数是十进制 uint32，解析器拒绝负数、
超出 UINT32_MAX 的数及非法尾字符。参数真实来自请求，并经过
`main → dispatch_request → handle_* → plan_*` 调用链。

三条缺陷边界路径：

| 样本 | 输入 | 数学结果 | uint32 实际分配大小 |
|---|---|---|---|
| cedar_router | 65537 × 65537 | 4295098369 | 131073 |
| harbor_nas | 4294963200 + 8192 | 4294971392 | 4096 |
| meadow_nvr | 1048577 × 4096 | 4294971392 | 4096 |

均可绕过 1 MiB 配额限制并接受错误的预留大小。这里实际执行回绕、检查和 malloc，
不模拟后续闪存写入或大数据拷贝，因此验证的是 CWE-190 导致的错误分配/配额绕过，
不是已经证明的越界写或代码执行。响应不泄漏预期漏洞标签。

## Ubuntu / WSL 编译

```bash
sudo apt update
sudo apt install build-essential python3
cd /mnt/c/Users/ROG/Desktop/mango_0/samples/httpd_firmware
bash build.sh
python3 verify.py
file bin/*_httpd
```

`bin/` 下生成 10 个没有扩展名的 ELF。默认编译为当前 Linux 主机架构
（通常 x86-64），但关键变量均为 uint32，所以 32 位回绕不依赖主机指针宽度。
脚本用 `-O0 -fno-inline -fno-pie -no-pie` 并保留函数符号，方便定位、反编译和追踪。
这些是可重复的分析条件，不代表真实厂商固件通常不优化。

可选 ARM32 交叉编译（先备份已有 bin；同名文件会覆盖）：

```bash
sudo apt install gcc-arm-linux-gnueabi
CC=arm-linux-gnueabi-gcc bash build.sh
```

ARM 二进制可交给 angr；`verify.py` 直接运行本机架构程序，不能直接运行 ARM ELF，
需要 ARM 机器或另行配置 QEMU 和对应运行库。

## 请求测试

```bash
./bin/cedar_router_httpd < requests/cedar_router_httpd_normal.http
./bin/cedar_router_httpd < requests/cedar_router_httpd_boundary.http
```

`verify.py` 检查 10 个程序的正常请求、边界请求及格式错误请求，共 30 项。
正常请求应返回 200；3 个缺陷样本的边界请求返回 200 且分配长度回绕；
7 个保护样本的边界请求返回 413；格式错误请求返回 400。

## 使用 Mango

在已安装本仓库及 angr 依赖的环境运行：

```bash
mango bin/cedar_router_httpd -c intoverflow --results results/cedar_router

# 先检查静态阶段候选点
mango bin/cedar_router_httpd -c intoverflow --skip-llm --results static/cedar_router

# 批量完整分析（会调用配置的 LLM API）
for binary in bin/*_httpd; do
    mango "$binary" -c intoverflow --results "results/$(basename "$binary")"
done
```

## 与当前检测器的对应关系

- 关键运算使用两个请求来源的运行时值，避免常量操作数和 add-immediate-1 过滤。
- 算术结果通过 `*bytes = size` 存储，并用于配额检查和分配，目标是命中 value_arith。
- 缺陷操作直接以 uint32 相加或相乘，没有先扩宽。
- 保护样本故意保留可分析的变量算术，用于评估模型是否识别支配运算的检查。
- 宽位安全样本可能被位宽筛选提前排除，这也是合理结果。
- 解析器、路由、地址运算可能产生额外候选点；一个二进制不等于一个 sink。
- `manifest.json` 的 `target_function` 指明目标函数；标签和理由在外部文件中，
  不应作为 LLM 输入，以免答案泄漏。

**预期是源码级 ground truth，不保证当前 angr/LLM 输出恰好 3 个 yes。**
编译器、体系结构、RDA 恢复及启发式过滤会影响候选点。需要核对实际 sink 的函数、
地址与反编译代码；没有报告不能视为已经证明安全。

`generate.py` 可重建源码、HTTP 请求和 manifest；会覆盖同名生成文件。
