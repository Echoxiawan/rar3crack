/*
 * stub_backends.cpp - provide non-available backend symbols on platforms /
 * builds that don't include the real GPU implementation, keeping the linker
 * happy and the "auto" selector clean.
 *
 * Real implementations live in:
 *   backends/metal_backend.mm   (macOS, compiled when RAR3_HAVE_METAL)
 *   backends/opencl_backend.cpp (when RAR3_HAVE_OPENCL)
 *   backends/cuda_backend.cu    (when RAR3_HAVE_CUDA)
 * Guard the stubs with the same macros so we never duplicate symbols.
 */
#include "backend.h"

#if !defined(RAR3_HAVE_METAL)
extern "C" const rar3_backend *rar3_backend_metal(void) { return nullptr; }
#endif

#if !defined(RAR3_HAVE_OPENCL)
extern "C" const rar3_backend *rar3_backend_opencl(void) { return nullptr; }
#endif

#if !defined(RAR3_HAVE_CUDA)
extern "C" const rar3_backend *rar3_backend_cuda(void) { return nullptr; }
#endif
