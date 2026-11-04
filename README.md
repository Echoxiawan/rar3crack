<div align="center">

# rar3crack

**RAR3 (RAR v4) 压缩包密码恢复工具 · GPU 优先 · 跨平台 · 零加密库依赖**

[![build](https://img.shields.io/github/actions/workflow/status/Echoxiawan/rar3crack/build.yml?style=flat-square&label=build)](https://github.com/Echoxiawan/rar3crack/actions/workflows/build.yml)
![platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-blue?style=flat-square)
![language](https://img.shields.io/badge/C%2B%2B-17-00599C?style=flat-square)
[![license](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
![status](https://img.shields.io/badge/backends-CPU%20%7C%20Metal%20%7C%20OpenCL%20%7C%20CUDA-orange?style=flat-square)

*macOS Metal · NVIDIA CUDA · OpenCL · 多线程 CPU —— 自动选最快后端，跑不动就回落 CPU*

</div>

---

## 目录

- [为什么用它](#为什么用它)
- [特性](#特性)
- [性能与搜索空间](#性能与搜索空间)
- [快速开始](#快速开始)
- [使用方法](#使用方法)
- [后端与自动选择](#后端与自动选择)
- [自动构建 / 发布](#自动构建--发布)
- [算法原理](#算法原理)
- [项目结构](#项目结构)
- [常见问题（FAQ）](#常见问题faq)
- [路线图](#路线图)
- [贡献](#贡献)
- [合规声明](#合规声明)
- [致谢](#致谢)
- [License](#license)

## 为什么用它

忘记 RAR3（RAR v4）压缩包密码时，通用解压工具只能逐个人工试，hashcat 功能全面但要记参数、配驱动。
rar3crack 把 RAR3 密码校验算法完整内置——开箱即用、跨平台、GPU 优先，且不依赖任何第三方加密库。
重度场景可配合 hashcat：`--extract-hash` 能直接导出与 hashcat `m12500` 兼容的目标。

| | rar3crack | hashcat | 手工 / 通用解压工具 |
|---|---|---|---|
| 专注 RAR3（RAR v4） | ✅ 开箱即用 | ✅ 需记参数 `-m 12500` | ❌ 只能逐个人工试 |
| GPU 加速 | ✅ Metal/CUDA/OpenCL | ✅ | ❌ |
| 无第三方加密依赖 | ✅ 内置 SHA1+AES | ⚠️ 依赖 OpenCL/驱动 | — |
| Apple Silicon 原生 | ✅ Metal（绕过坏的 cl2Metal） | ⚠️ Metal 后端常编不过 | — |
| 一键拿参数喂 hashcat | ✅ `--extract-hash` | — | — |
| 跨平台 CI 出货 | ✅ 三平台自动构建 | — | — |

> 简单说：**能直接用、跨平台、算法透明**。重度场景仍建议配合 hashcat。

## 特性

- 🎯 **精确的 RAR3 KDF**：完整还原 unrar `crypt3.cpp` 的 `SetKey30` 与
  `sha1_process_rar29` 的**扩展字回写**机制
- 🔑 **UTF-16LE 密码编码**：正确复刻 RAR 的 `WideToRaw`（这是绝大多数实现出错的地方）
- 🧮 **零第三方加密依赖**：内置 SHA1 + AES-128-CBC，编译即用
- 🚀 **多后端可插拔**：CPU（多线程）· Metal（macOS 原生 MSL）· OpenCL · CUDA
- 🧠 **自动后端选择**：`metal → cuda → opencl → cpu`，不可用自动回落
- 🗂️ **攻击模式**：字典攻击 + 数字掩码爆破
- ✅ **官方向量自校准**：用 hashcat `m12500` 向量验证核心算法（`tests/selftest.cpp`）
- 🖥️ **三平台 CI**：GitHub Actions 自动产出 macOS / Windows / Linux 可执行文件

## 性能与搜索空间

RAR3 每个候选密码需迭代 **0x40000（262144）轮 SHA1**，属先天计算密集型。
以下为本项目在 **Apple M4** 上的实测速率（仅供参考）：

| 后端 | 速率（约） | 备注 |
|---|---|---|
| CPU（10 线程） | ~800 p/s | 全平台可用 |
| Metal（M4 GPU） | ~2300 p/s | 原生 MSL，绕过损坏的 cl2Metal |

> GPU 具体速率取决于显卡；CUDA/OpenCL 通常远高于 CPU。
> 想更快？见 [路线图](#路线图) 的 SIMD/warp 级并行。

**搜索空间估算（N 位纯数字，首位非 0）：**

| 位数 | 组合数 | CPU (800/s) | Metal (2300/s) |
|---|---|---|---|
| 6 | 90 万 | ~19 分钟 | ~7 分钟 |
| 7 | 900 万 | ~3 小时 | ~1 小时 |
| 8 | 9000 万 | ~31 小时 | ~11 小时 |
| 9 | 9 亿 | ~13 天 | ~4.5 天 |
| 10 | 90 亿 | ~130 天 | ~45 天 |

> 🎯 **结论：纯数字全空间爆破代价极高**，请优先用字典 + 常见规律
> （生日、手机号、年份、重复/顺子）命中，而不是硬刚全空间。

## 快速开始

依赖：**CMake ≥ 3.16**，支持 **C++17** 的编译器。

### 三种构建方式

**① 本地一键脚本**

```bash
# macOS / Linux
./scripts/build.sh              # macOS 默认含 Metal
./scripts/build.sh --opencl     # 追加 OpenCL

# Windows
scripts\build.bat
scripts\build.bat --opencl
```

**② 手动 CMake**

<details>
<summary><b>macOS</b>（默认启用 Metal）</summary>

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/selftest          # 期望输出 MATCH
```
</details>

<details>
<summary><b>Windows</b>（默认 CPU，可加 OpenCL/CUDA）</summary>

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
.\build\Release\selftest.exe
```

GPU 变体：
- NVIDIA：`-DRAR3_WITH_CUDA=ON`（需 CUDA Toolkit）
- 通用（Intel/AMD/NVIDIA）：`-DRAR3_WITH_OPENCL=ON`（需 OpenCL SDK）
</details>

<details>
<summary><b>Linux</b></summary>

```bash
sudo apt-get install -y cmake build-essential ocl-icd-opencl-dev   # OpenCL 可选
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DRAR3_WITH_OPENCL=ON
cmake --build build -j
./build/selftest
```
</details>

**③ 直接下载 CI 产物**（见 [自动构建](#自动构建--发布)）

### 第一步：跑通自测

```bash
./build/selftest
# 输出：
# [selftest] pw=hashcat  -> MATCH  (core OK)
# [selftest] pw=wrongpwd -> NO MATCH (expected)
```

> 这一步验证核心算法（KDF + AES）正确。**没 MATCH 就不要往下用**——说明构建或平台异常。

## 使用方法

```bash
# ① 字典攻击
rar3crack archive.rar -w wordlist.txt

# ② 爆破 8 位纯数字（首位 1-9）
rar3crack archive.rar -d 8

# ③ 指定后端
rar3crack archive.rar -w wordlist.txt -b metal     # macOS
rar3crack archive.rar -d 8            -b cuda      # NVIDIA
rar3crack archive.rar -w wordlist.txt -b cpu       # 强制 CPU

# ④ 仅提取加密参数（salt / 前 16 字节密文），用于调试或喂给 hashcat
rar3crack archive.rar --extract-hash
```

命中时输出：

```text
*** FOUND: yourpassword ***
```

未命中输出 `not found (N candidates)`，退出码非 0，便于脚本判断。

### 命令行选项

| 选项 | 说明 |
|---|---|
| `-w, --wordlist FILE` | 字典文件（每行一个候选） |
| `-d, --digits N` | 爆破 N 位纯数字（首位 1-9） |
| `-b, --backend NAME` | `cpu` \| `metal` \| `opencl` \| `cuda` \| `auto`（默认 auto） |
| `-t, --threads N` | CPU 线程数（预留，当前版本不生效，后端自动取全部核心） |
| `--extract-hash` | 只打印 salt/enc 目标并退出 |
| `-q, --quiet` | 精简输出 |
| `-h, --help` | 显示帮助 |

> ⚠️ 密码长度上限 **16 字节**（UTF-8 输入，超长候选会被截断）。字典攻击请先确认目标密码不超过此长度。

### 导出给 hashcat

```bash
# 1) 拿参数
./rar3crack archive.rar --extract-hash
#   salt=...   enc16=...

# 2) 拼成 hashcat m12500 格式
#   $RAR3$*0*<salt>*<enc16>
hashcat -m 12500 hash.txt wordlist.txt
```

## 后端与自动选择

`-b auto`（默认）按 **`metal → cuda → opencl → cpu`** 顺序选第一个可用的；
指定后端在本机不可用时，自动回落 CPU 并提示。

| 后端 | 平台 | 状态 |
|---|---|---|
| CPU | 全平台 | ✅ 完整可用 |
| Metal | macOS (Apple Silicon) | ✅ 完整，已用官方向量验证 |
| OpenCL | Windows / Linux / macOS | 🚧 骨架 + [移植指南](docs/PORTING.md) |
| CUDA | NVIDIA | 🚧 骨架 + [移植指南](docs/PORTING.md) |

> 💡 关于 macOS GPU 读数：`ioreg` / iStat 显示的 `Device Utilization` 是**档位峰值**，
> 跑过 GPU 后可能长时间停在 100%，这不代表程序残留或硬件故障
> （`recoveryCount=0` 即证明）。本项目 Metal 后端已做资源即时释放 + GPU drain，
> 不会留下未回收的 GPU 工作。

## 自动构建 / 发布

### CI 三平台产物

`.github/workflows/build.yml` 在 push / PR / tag 时自动构建，并**每次运行 `selftest`**：

| 平台 | Runner | 产物 | GPU |
|---|---|---|---|
| macOS | `macos-14` (arm64) | `rar3crack-macos-arm64.tar.gz` | Metal |
| Windows | `windows-latest` | `rar3crack-windows-x64.zip` | CPU + OpenCL |
| Linux | `ubuntu-22.04` | `rar3crack-linux-x64.tar.gz` | CPU + OpenCL |

### 发布（打 tag 触发 Release）

推 `v*` 标签即触发构建并自动创建 **GitHub Release**，附上三平台产物。
本地用 `scripts/release.sh` 一键打 tag 推送（**该脚本不入库**，见 `.gitignore`）：

```bash
./scripts/release.sh                 # 自动递增补丁号（无 tag 从 v0.1.0 起）
./scripts/release.sh 1.0.0           # 指定版本号
./scripts/release.sh 1.0.0 -m "msg"  # 自定义 tag 说明
./scripts/release.sh --dry-run       # 预览，不实际推送
```

脚本会校验版本格式、tag 冲突、`origin` 配置，推送后打印 Actions / Release 链接。

## 算法原理

RAR3 密码校验流程：

1. 密码编码为 **UTF-16LE**，追加 8 字节 `salt`
2. 迭代 **0x40000 轮** SHA1，每轮追加 3 字节小端计数器 `le24(I)`；
   其中 `sha1_process_rar29` 会在每个 64 字节块后把扩展字**回写**进源数据流
3. 迭代结束的最终摘要派生 **16 字节 AES-128 key**；
   每 `0x40000/16` 轮采样一次 `digest[4]` 低字节，凑成 **16 字节 IV**
4. 用 AES-128-CBC 解密加密头前 16 字节，若明文以 `C4 3D 7B 00 40 07 00 00` 开头即密码正确

> 核心实现见 [`src/rar3.cpp`](src/rar3.cpp)；移植到其他 GPU 见 [`docs/PORTING.md`](docs/PORTING.md)。

## 项目结构

```
rar3crack/
├── .github/workflows/build.yml   跨平台 CI 自动构建
├── CMakeLists.txt
├── include/
│   ├── rar3.h                    核心 KDF / 校验 API
│   └── backend.h                 后端抽象接口
├── src/
│   ├── rar3.cpp                  RAR3 KDF + SHA1(rar29) + AES-128（纯 C++）
│   └── main.cpp                  CLI + RAR 解析 + 候选生成 + 后端调度
├── backends/
│   ├── cpu_backend.cpp           多线程 CPU
│   ├── metal_backend.mm          macOS Metal（原生 MSL）
│   ├── opencl_backend.cpp        OpenCL（骨架，见 docs/PORTING.md）
│   ├── cuda_backend.cu           CUDA（骨架，见 docs/PORTING.md）
│   └── stub_backends.cpp         未启用后端时的占位
├── tests/selftest.cpp            官方向量自校准
├── scripts/{build.sh, build.bat} 本地一键构建
├── docs/PORTING.md               Metal → OpenCL/CUDA 移植指南
└── CONTRIBUTING.md               贡献指南
```

## 常见问题（FAQ）

<details>
<summary><b>报错 "not a RAR4 archive" / 找不到加密头</b></summary>

本工具只支持 **RAR3 / RAR v4**。RAR5（`$RAR5`）算法不同，暂未支持。
用 `file archive.rar` 或解压工具确认版本。
</details>

<details>
<summary><b>selftest 没有输出 MATCH</b></summary>

说明核心算法在你平台构建异常。请确认：① 用的是 Release 构建；
② 没有改过 `src/rar3.cpp`；③ 编译器没有做非标准优化。可开 issue 附平台信息。
</details>

<details>
<summary><b>GPU 跑完利用率显示 100% 下不来</b></summary>

见 [后端与自动选择](#后端与自动选择) 里的说明：这是 macOS `ioreg`/iStat 的档位峰值读数，
非程序残留（`recoveryCount=0`）。重启系统可重置读数。本项目已做资源即时释放。
</details>

<details>
<summary><b>能用它破解别人的压缩包吗？</b></summary>

不能，也不应。本项目仅限**你自己拥有或已获授权**的压缩包（找回密码、CTF、取证、
安全研究）。使用前请阅读 [合规声明](#合规声明)。
</details>

<details>
<summary><b>能处理中文密码 / 特殊字符吗？</b></summary>

能。密码按 UTF-8 输入，内部转 **UTF-16LE** 参与 KDF，与 RAR 原生行为一致。
注意中文密码按 UTF-8 编码后每字占 3 字节，**最长约 5 个汉字**（16 字节上限）。
</details>

## 路线图

- [x] 核心 RAR3 KDF + CPU 后端
- [x] macOS Metal 后端
- [x] 三平台 CI 自动构建
- [ ] OpenCL 内核（[移植指南已就绪](docs/PORTING.md)）
- [ ] CUDA 内核（[移植指南已就绪](docs/PORTING.md)）
- [ ] SIMD/warp 级并行加速（32 路共享指令流）
- [ ] 规则引擎 / 日期·手机号掩码预设
- [ ] RAR5（AES + PBKDF2）支持

## 贡献

欢迎 PR！请先阅读 [`CONTRIBUTING.md`](CONTRIBUTING.md)。
改动核心算法后务必确认 `selftest` 仍输出 `MATCH`——这是唯一的真理锚点。

## 合规声明

本项目仅用于**你自己拥有或已获明确授权**的压缩包密码恢复（忘记密码、CTF 竞赛、
数字取证、安全研究）。**禁止**用于未授权访问他人数据。使用者须自行遵守所在地法律法规，
因滥用产生的一切后果由使用者自负。

## 致谢

- RAR3 算法参考 unrar 开源实现（`crypt3.cpp` / `sha1.cpp`）
- 测试向量来自 hashcat `m12500`（RAR3-hp）

## License

[MIT](LICENSE) © 2026 rar3crack contributors
