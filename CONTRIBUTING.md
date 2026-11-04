# Contributing to rar3crack

感谢参与！本项目致力于做一个干净、可移植、GPU 优先的 RAR3 密码恢复工具。

## 快速开始

```bash
# macOS / Linux
./scripts/build.sh
./build/selftest          # 必须输出 MATCH

# Windows
scripts\build.bat
build\Release\selftest.exe
```

## 提交前自检

1. `selftest` 必须通过（官方向量 `pw="hashcat"` 命中）。
2. 改动核心算法（`src/rar3.cpp`）后，务必确认 `selftest` 仍 MATCH——这是唯一真理锚点。
3. 新增/修改 GPU 内核后，用同一官方向量在对应设备上自测一次再提 PR。
4. 保持 `auto` 后端候选顺序：`metal → cuda → opencl → cpu`，且不可用要能优雅回落。

## 想贡献的方向（欢迎）

- [ ] 补齐 OpenCL 内核（见 [`docs/PORTING.md`](docs/PORTING.md)）
- [ ] 补齐 CUDA 内核（见 [`docs/PORTING.md`](docs/PORTING.md)）
- [ ] SIMD/warp 级并行加速（32 路共享指令流）
- [ ] 更多候选生成：规则引擎、日期/手机号掩码预设
- [ ] RAR5（AES + PBKDF2）支持
- [ ] 更多压缩格式（保持模块化）

## 代码风格

- C++17，无第三方加密库依赖（AES/SHA1 自带）。
- 新后端实现 `rar3_backend` 接口（`include/backend.h`）即可插拔。
- 平台相关代码用 CMake 宏隔离：`RAR3_HAVE_METAL` / `RAR3_HAVE_OPENCL` / `RAR3_HAVE_CUDA`。

## 提交流程

1. Fork → 分支 → 改动
2. 确保 `selftest` 通过（本地/CI）
3. 提 PR，描述改了什么、怎么验证的

## 合规

本项目仅用于**自己拥有或已获授权**的压缩包密码恢复（忘记密码、CTF、取证、
安全研究）。禁止用于未授权访问他人数据。贡献代码即视为认同此约定。
