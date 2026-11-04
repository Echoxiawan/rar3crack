# RAR3 内核移植指南（Metal → OpenCL / CUDA）

本文件说明如何把已验证的 **Metal MSL 内核**（`backends/metal_backend.mm`）移植为
**OpenCL C** 和 **CUDA**，让 `opencl_backend.cpp` / `cuda_backend.cu` 真正工作。
算法本身（SHA1 + RAR29 回写 + AES-128 + 校验）已用 hashcat m12500 官方向量校准，
移植时**只用改语法，不改逻辑**。

---

## 0. 三个后端共享的算法骨架

每个 GPU 线程处理**一个候选密码**，步骤固定：

```
1. password (ASCII bytes) 逐字节扩成 UTF-16LE: c -> c, 0x00
2. RawPsw = password_utf16 || salt(8)
3. SHA1 上下文初始化
4. for I in 0 .. 0x40000-1:
      buf = RawPsw 的副本
      sha1_process_rar29(buf, len)      // 含"扩展字回写"到 buf
      sha1_process(le24(I), 3)          // 3 字节小端计数器
      if I % (0x40000/16) == 0:
          digest = sha1_done(copy of ctx)
          AESInit[I/(0x40000/16)] = digest[4] & 0xFF
5. digest = sha1_done(ctx)
   AESKey[i*4+j] = (digest[i] >> (j*8)) & 0xFF   (i,j in 0..3)
6. dec = AES128_decrypt_block(AESKey, enc[0..15])
   out[i] = dec[i] ^ AESInit[i]
7. match  <=>  out[0..7] == C4 3D 7B 00 40 07 00 00
```

**唯一的坑（务必保留）**：密码必须先转 **UTF-16LE** 再参与 KDF。
丢掉这步，密码对了也永远不命中。

---

## 1. SHA1 的 RAR29 变体（三者一致）

标准 SHA1 之外，RAR3 有 `sha1_process_rar29`：每处理完一个完整 64 字节块，
把该块**扩展后的 16 个字**（big-endian 词）**写回源数据流的对应位置**，污染下一块。
这就是普通 SHA1 库算不出来的原因。

参考实现已在 `src/rar3.cpp` 的 `sha1_process_rar29()` 和 `metal_backend.mm` 的
`sc_process_rar29()`。移植时注意：

- SHA1 内部按 **big-endian** 组装 16 个 `uint32` 字
- 回写时写回的是**同一组已装载的字**（等价于重算该块的 16 个字再大端写回）
- 计数器 `le24(I)` 走**普通** `sha1_process`（无回写）

---

## 2. 移植到 OpenCL（`backends/opencl_backend.cpp`）

### 语法替换表

| Metal (MSL) | OpenCL C |
|---|---|
| `thread` 地址空间 | 无（局部变量默认私有）；显式用 `__private` |
| `device` 参数 | `__global` |
| `constant` | `__constant` |
| `uchar` / `uint` / `ulong` | 同名可用 |
| `kernel void f(...)` | `__kernel void f(...)` |
| `thread_position_in_grid` | `get_global_id(0)` |
| `threadgroup const uint& count` | 直接传 `__global const uint*` 或 `__constant` |
| `rotl(x,n)` | `rotate(x,n)` |

### 结构体

```c
typedef struct { uint state[5]; ulong count; uchar buffer[64]; uint bufw; } sctx;
```

注意 OpenCL 里 `ulong` 是 64 位，和 MSL 一致；`count` 用 `ulong`。

### 编译

```
cmake -S . -B build -DRAR3_WITH_OPENCL=ON
```

需要 OpenCL SDK（Linux: `ocl-icd-opencl-dev`；Windows: vendor SDK）。
kernel 用 `clBuildProgram` 从字符串编译（参照 `opencl_backend.cpp` 里 `kCL`）。

> 💡 小技巧：把 MSL 的 kernel 主体几乎原样拷进 OpenCL C，把
> `thread/device/constant` 换成 `__private/__global/__constant`，把
> `thread_position_in_grid` 换成 `get_global_id(0)`，基本就通了。

---

## 3. 移植到 CUDA（`backends/cuda_backend.cu`）

### 语法替换表

| Metal (MSL) | CUDA |
|---|---|
| `thread` 地址空间 | 无（局部变量默认私有） |
| `device` 参数 | 普通指针（全局内存） |
| `constant` | `__constant__` 或普通参数 |
| `kernel void f(...)` | `__global__ void f(...)` |
| `thread_position_in_grid` | `blockIdx.x*blockDim.x + threadIdx.x` |
| `rotl(x,n)` | `__funnelshift_l` / 手写 `(x<<n)|(x>>(32-n))` |
| `simd` 内建 | `__shfl_*`（可选优化） |

### 启动

```cuda
int threads = 256;
int blocks = (count + threads - 1) / threads;
rar3_crack_kernel<<<blocks, threads>>>(pwbuf, pwlen, salt, enc, result, count);
```

### 编译

```
cmake -S . -B build -DRAR3_WITH_CUDA=ON
```

需要 CUDA Toolkit（`nvcc`）。CMake 里 `enable_language(CUDA)` 已就绪。

---

## 4. 验证移植是否正确

**只认一个标准**：用官方向量能命中。

```
pw   = "hashcat"
salt = 45109af8ab5f297a
enc  = adbf6c5385d7a40373e8f77d7b89d317
期望解密 out[0..7] = c4 3d 7b 00 40 07 00 00
```

做法：先用 `--extract-hash` 拿到参数，或在测试里硬编码这组向量，
确认你的 GPU 内核 `result` 里对应 `"hashcat"` 的项返回 1。
`tests/selftest.cpp` 覆盖的是 CPU 核心；GPU 后端请用同样向量自测一次再合入。

---

## 5. 性能调优提示

- **threadgroup / block size**：Metal 用 `maxTotalThreadsPerThreadgroup`，OpenCL 查
  `CL_DEVICE_MAX_WORK_GROUP_SIZE`，CUDA 用 128~256 起步。
- **每次派发批量**：`metal_backend.mm` 用 `CHUNK = 200000` 分批提交，避免超长单个 command。
- **寄存器压力**：SHA1 展开 80 步 + AES 密钥扩展吃寄存器，block 太大反而降速。
- **进阶**：真正提速靠 **warp/SIMD 级并行**——一个 lane 一个密码，32 路共享指令流
  （SHA1 的每一步用 `shfl` 广播常量）。这是 hashcat 快的真正秘密，但工作量大。
  当前实现是"一线程一密码"，已能跑通且正确，作为起点足够。

---

## 6. 已针对的平台现状

| 后端 | 状态 |
|---|---|
| CPU | ✅ 完整、可直接用 |
| Metal | ✅ 完整、Mac 上验证过官方向量 |
| OpenCL | 🚧 骨架 + 本指南，kernel 待据此填充 |
| CUDA | 🚧 骨架 + 本指南，kernel 待据此填充 |

欢迎按本指南补齐 OpenCL/CUDA 并提 PR。
