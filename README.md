<div align="center">

# rar3crack

**RAR3 (RAR v4) archive password recovery · GPU-first · Cross-platform · Zero crypto dependencies**

[![build](https://img.shields.io/github/actions/workflow/status/Echoxiawan/rar3crack/build.yml?style=flat-square&label=build)](https://github.com/Echoxiawan/rar3crack/actions/workflows/build.yml)
![platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-blue?style=flat-square)
![language](https://img.shields.io/badge/C%2B%2B-17-00599C?style=flat-square)
[![license](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
![status](https://img.shields.io/badge/backends-CPU%20%7C%20Metal%20%7C%20OpenCL%20%7C%20CUDA-orange?style=flat-square)

*macOS Metal · NVIDIA CUDA · OpenCL · multi-threaded CPU — picks the fastest backend automatically, falls back to CPU when GPUs are unavailable*

**English** | [简体中文](README.zh-CN.md)

</div>

---

## Table of Contents

- [Why rar3crack](#why-rar3crack)
- [Features](#features)
- [Performance & Search Space](#performance--search-space)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Backends & Auto-Selection](#backends--auto-selection)
- [CI Builds / Releases](#ci-builds--releases)
- [How the Algorithm Works](#how-the-algorithm-works)
- [Project Layout](#project-layout)
- [FAQ](#faq)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Legal Notice](#legal-notice)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## Why rar3crack

When you forget the password of a RAR3 (RAR v4) archive, generic unarchivers can only try guesses by hand,
and hashcat — while powerful — wants the right flags and a working driver stack.
rar3crack ships the full RAR3 password-verification algorithm out of the box: cross-platform, GPU-first,
with no third-party crypto dependencies. For heavy workloads it plays well with hashcat too:
`--extract-hash` exports a target directly compatible with hashcat's `m12500`.

| | rar3crack | hashcat | Manual / generic unarchivers |
|---|---|---|---|
| RAR3 (RAR v4) focus | ✅ Works out of the box | ✅ Needs `-m 12500` | ❌ Guess by hand only |
| GPU acceleration | ✅ Metal / CUDA / OpenCL | ✅ | ❌ |
| No third-party crypto deps | ✅ Built-in SHA1 + AES | ⚠️ Depends on OpenCL / drivers | — |
| Native on Apple Silicon | ✅ Metal (bypasses broken cl2Metal) | ⚠️ Metal backend often fails to build | — |
| One-command hash for hashcat | ✅ `--extract-hash` | — | — |
| Cross-platform CI artifacts | ✅ 3-platform auto builds | — | — |

> In short: **ready to run, cross-platform, algorithmically transparent**. For heavy workloads we still recommend pairing with hashcat.

## Features

- 🎯 **Exact RAR3 KDF** — faithfully reproduces unrar's `crypt3.cpp` `SetKey30`, including the
  **expanded-word write-back** in `sha1_process_rar29`
- 🔑 **UTF-16LE password encoding** — correctly replicates RAR's `WideToRaw` (where most reimplementations go wrong)
- 🧮 **Zero third-party crypto dependencies** — built-in SHA1 + AES-128-CBC; compiles and runs anywhere
- 🚀 **Pluggable multi-backend** — CPU (multi-threaded) · Metal (native MSL on macOS) · OpenCL · CUDA
- 🧠 **Automatic backend selection** — `metal → cuda → opencl → cpu`, with graceful fallback
- 🗂️ **Attack modes** — dictionary attack + digit-mask brute force
- ✅ **Official-vector self-test** — validates the core against hashcat `m12500` vectors (`tests/selftest.cpp`)
- 🖥️ **3-platform CI** — GitHub Actions builds macOS / Windows / Linux binaries on every push

## Performance & Search Space

Each candidate password costs **0x40000 (262,144) SHA1 rounds**, so RAR3 is inherently compute-bound.
Measured throughput on an **Apple M4** (for reference only):

| Backend | Throughput (approx.) | Notes |
|---|---|---|
| CPU (10 threads) | ~800 p/s | Works on every platform |
| Metal (M4 GPU) | ~2300 p/s | Native MSL, bypasses broken cl2Metal |

> Actual GPU throughput depends on the card; CUDA/OpenCL typically far exceed CPU.
> Want more speed? See [Roadmap](#roadmap) for SIMD/warp-level parallelism.

**Search-space estimates (N-digit numeric PINs, no leading zero):**

| Digits | Combinations | CPU (800/s) | Metal (2300/s) |
|---|---|---|---|
| 6 | 900 K | ~19 min | ~7 min |
| 7 | 9 M | ~3 h | ~1 h |
| 8 | 90 M | ~31 h | ~11 h |
| 9 | 900 M | ~13 days | ~4.5 days |
| 10 | 9 B | ~130 days | ~45 days |

> 🎯 **Bottom line: brute-forcing the full numeric space is expensive.** Prefer a dictionary plus common
> patterns (birthdays, phone numbers, years, repeats/sequences) over raw full-space searches.

## Quick Start

Requirements: **CMake ≥ 3.16** and a compiler with **C++17** support.

### Three ways to build

**① One-shot local script**

```bash
# macOS / Linux
./scripts/build.sh              # macOS enables Metal by default
./scripts/build.sh --opencl     # additionally enable OpenCL

# Windows
scripts\build.bat
scripts\build.bat --opencl
```

**② Manual CMake**

<details>
<summary><b>macOS</b> (Metal enabled by default)</summary>

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/selftest          # expect MATCH
```
</details>

<details>
<summary><b>Windows</b> (CPU by default; OpenCL/CUDA optional)</summary>

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
.\build\Release\selftest.exe
```

GPU variants:
- NVIDIA: `-DRAR3_WITH_CUDA=ON` (requires the CUDA Toolkit)
- Generic (Intel/AMD/NVIDIA): `-DRAR3_WITH_OPENCL=ON` (requires an OpenCL SDK)
</details>

<details>
<summary><b>Linux</b></summary>

```bash
sudo apt-get install -y cmake build-essential ocl-icd-opencl-dev   # OpenCL optional
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DRAR3_WITH_OPENCL=ON
cmake --build build -j
./build/selftest
```
</details>

**③ Download CI artifacts directly** (see [CI Builds / Releases](#ci-builds--releases))

### Step one: run the self-test

```bash
./build/selftest
# Output:
# [selftest] pw=hashcat  -> MATCH  (core OK)
# [selftest] pw=wrongpwd -> NO MATCH (expected)
```

> This verifies the core algorithm (KDF + AES) is correct on your machine. **Do not proceed without a MATCH** —
> it means the build or platform is misbehaving.

## Usage

```bash
# ① Dictionary attack
rar3crack archive.rar -w wordlist.txt

# ② Brute-force 8-digit PINs (first digit 1-9)
rar3crack archive.rar -d 8

# ③ Pick a backend explicitly
rar3crack archive.rar -w wordlist.txt -b metal     # macOS
rar3crack archive.rar -d 8            -b cuda      # NVIDIA
rar3crack archive.rar -w wordlist.txt -b cpu       # force CPU

# ④ Extract crypto parameters only (salt / first 16 ciphertext bytes), for debugging or hashcat
rar3crack archive.rar --extract-hash
```

Output on a hit:

```text
*** FOUND: yourpassword ***
```

On a miss it prints `not found (N candidates)` and exits non-zero, which makes scripting easy.

### Command-line options

| Option | Description |
|---|---|
| `-w, --wordlist FILE` | Dictionary file (one candidate per line) |
| `-d, --digits N` | Brute-force N-digit PINs (first digit 1-9) |
| `-b, --backend NAME` | `cpu` \| `metal` \| `opencl` \| `cuda` \| `auto` (default: auto) |
| `-t, --threads N` | CPU threads (reserved; not yet effective — the backend auto-uses all cores) |
| `--extract-hash` | Print the salt/enc target and exit |
| `-q, --quiet` | Quieter output |
| `-h, --help` | Show help |

> ⚠️ Passwords are capped at **16 bytes** (input as UTF-8; longer candidates are truncated). For dictionary
> attacks, make sure your target password fits within this limit.

### Export for hashcat

```bash
# 1) Grab the parameters
./rar3crack archive.rar --extract-hash
#   salt=...   enc16=...

# 2) Assemble the hashcat m12500 format
#   $RAR3$*0*<salt>*<enc16>
hashcat -m 12500 hash.txt wordlist.txt
```

## Backends & Auto-Selection

`-b auto` (default) picks the first available backend in **`metal → cuda → opencl → cpu`** order;
an explicitly requested backend that is unavailable falls back to CPU with a warning.

| Backend | Platform | Status |
|---|---|---|
| CPU | All platforms | ✅ Fully working |
| Metal | macOS (Apple Silicon) | ✅ Fully working, verified against official vectors |
| OpenCL | Windows / Linux / macOS | 🚧 Skeleton + [porting guide](docs/PORTING.md) |
| CUDA | NVIDIA | 🚧 Skeleton + [porting guide](docs/PORTING.md) |

> 💡 About macOS GPU readings: the `Device Utilization` shown by `ioreg` / iStat is a **peak gear reading**.
> It can stay at 100% long after a GPU run — this is not a leaked program or a hardware fault
> (`recoveryCount=0` proves that). The Metal backend here releases resources immediately and drains the GPU,
> leaving no uncollected GPU work behind.

## CI Builds / Releases

### 3-platform CI artifacts

`.github/workflows/build.yml` builds on every push / PR / tag and **runs `selftest` each time**:

| Platform | Runner | Artifact | GPU |
|---|---|---|---|
| macOS | `macos-14` (arm64) | `rar3crack-macos-arm64.tar.gz` | Metal |
| Windows | `windows-latest` | `rar3crack-windows-x64.zip` | CPU |
| Linux | `ubuntu-22.04` | `rar3crack-linux-x64.tar.gz` | CPU + OpenCL |

### Releases (triggered by tags)

Pushing a `v*` tag triggers the build and auto-creates a **GitHub Release** with all three artifacts.
Locally, `scripts/release.sh` tags and pushes in one step (the script is **not tracked in git**, see `.gitignore`):

```bash
./scripts/release.sh                 # auto-increment patch version (starts at v0.1.0)
./scripts/release.sh 1.0.0           # specify a version
./scripts/release.sh 1.0.0 -m "msg"  # custom tag annotation
./scripts/release.sh --dry-run       # preview without pushing
```

The script validates the version format, tag conflicts and the `origin` remote, then prints the Actions / Release URLs.

## How the Algorithm Works

RAR3 password verification:

1. The password is encoded as **UTF-16LE** and the 8-byte `salt` is appended
2. **0x40000 rounds** of SHA1, each round appending a 3-byte little-endian counter `le24(I)`;
   `sha1_process_rar29` **writes the expanded words back** into the source stream after every 64-byte block
3. The final digest yields the **16-byte AES-128 key**; the low byte of `digest[4]` is sampled every
   `0x40000/16` rounds to assemble the **16-byte IV**
4. The first 16 bytes of the encrypted header are decrypted with AES-128-CBC; the password is correct
   if the plaintext starts with `C4 3D 7B 00 40 07 00 00`

> Core implementation: [`src/rar3.cpp`](src/rar3.cpp). Porting to other GPUs: [`docs/PORTING.md`](docs/PORTING.md).

## Project Layout

```
rar3crack/
├── .github/workflows/build.yml   cross-platform CI
├── CMakeLists.txt
├── include/
│   ├── rar3.h                    core KDF / verification API
│   └── backend.h                 backend abstraction interface
├── src/
│   ├── rar3.cpp                  RAR3 KDF + SHA1(rar29) + AES-128 (pure C++)
│   └── main.cpp                  CLI + RAR parsing + candidate generation + backend dispatch
├── backends/
│   ├── cpu_backend.cpp           multi-threaded CPU
│   ├── metal_backend.mm          macOS Metal (native MSL)
│   ├── opencl_backend.cpp        OpenCL (skeleton, see docs/PORTING.md)
│   ├── cuda_backend.cu           CUDA (skeleton, see docs/PORTING.md)
│   └── stub_backends.cpp         stubs for disabled backends
├── tests/selftest.cpp            official-vector self-test
├── scripts/{build.sh, build.bat} one-shot local build scripts
├── docs/PORTING.md               Metal → OpenCL/CUDA porting guide
└── CONTRIBUTING.md               contribution guide
```

## FAQ

<details>
<summary><b>It says "not a RAR4 archive" / can't find the encrypted header</b></summary>

This tool supports **RAR3 / RAR v4 only**. RAR5 (`$RAR5`) uses a different algorithm and is not yet
supported. Confirm the version with `file archive.rar` or your unarchiver.
</details>

<details>
<summary><b>selftest doesn't print MATCH</b></summary>

The core algorithm is misbehaving on your platform. Check: ① you built in Release mode;
② you haven't modified `src/rar3.cpp`; ③ your compiler isn't applying non-standard optimizations.
Please open an issue with your platform info.
</details>

<details>
<summary><b>GPU utilization sticks at 100% after a run</b></summary>

See the note in [Backends & Auto-Selection](#backends--auto-selection): it's a peak gear reading from
macOS `ioreg`/iStat, not leaked program state (`recoveryCount=0`). A reboot resets the reading. This
project already releases GPU resources immediately.
</details>

<details>
<summary><b>Can I use it to crack other people's archives?</b></summary>

No — and you shouldn't. This project is for archives **you own or are authorized to test** (password
recovery, CTF, forensics, security research). Please read the [Legal Notice](#legal-notice).
</details>

<details>
<summary><b>Does it handle non-ASCII passwords?</b></summary>

Yes. Passwords are input as UTF-8 and converted to **UTF-16LE** for the KDF, matching RAR's native
behavior. Note that after UTF-8 encoding the total length is still capped at **16 bytes** (e.g. at most
5 CJK characters).
</details>

## Roadmap

- [x] Core RAR3 KDF + CPU backend
- [x] macOS Metal backend
- [x] 3-platform CI builds
- [ ] OpenCL kernel ([porting guide ready](docs/PORTING.md))
- [ ] CUDA kernel ([porting guide ready](docs/PORTING.md))
- [ ] SIMD/warp-level parallelism (32 lanes sharing one instruction stream)
- [ ] Rule engine / date & phone-number mask presets
- [ ] RAR5 (AES + PBKDF2) support

## Contributing

PRs welcome! Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) first.
If you touch the core algorithm, make sure `selftest` still prints `MATCH` — it is the single source of truth.

## Legal Notice

This project is intended solely for recovering passwords of archives **you own or are explicitly
authorized to test** (forgotten passwords, CTF competitions, digital forensics, security research).
It must **not** be used to access other people's data without authorization. You are responsible for
complying with the laws of your jurisdiction; any consequences of misuse are borne by the user.

## Acknowledgments

- RAR3 algorithm reference: the unrar open-source implementation (`crypt3.cpp` / `sha1.cpp`)
- Test vectors from hashcat `m12500` (RAR3-hp)

## License

[MIT](LICENSE) © 2026 rar3crack contributors
