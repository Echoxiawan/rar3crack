/*
 * cuda_backend.cu - NVIDIA CUDA backend (optional).
 *
 * Build with -DRAR3_WITH_CUDA=ON and nvcc available. Runs one candidate per
 * CUDA thread. The __device__ SHA1(rar29) + AES-128 verifier mirrors the
 * validated Metal MSL kernel (metal_backend.mm) and can be ported largely
 * line-by-line. This file provides the structured skeleton + host harness so
 * the CMake option builds; fill in the device KDF to enable.
 */
#if defined(RAR3_HAVE_CUDA)
#include "backend.h"
#include "rar3.h"
#include <cuda_runtime.h>
#include <vector>
#include <chrono>
#include <cstdio>

__global__ void rar3_crack_kernel(const unsigned char *pwbuf,
                                  const unsigned int  *pwlen,
                                  const unsigned char *salt,
                                  const unsigned char *enc,
                                  int *result,
                                  unsigned int count)
{
    unsigned int gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= count) return;
    /* TODO: implement RAR3 OraIter KDF + AES-128 verify (port from MSL). */
    result[gid] = 0;
}

namespace {
int cuda_available() {
    int n = 0;
    if (cudaGetDeviceCount(&n) != cudaSuccess) return 0;
    return n > 0 ? 1 : 0;
}
int run_batch(const rar3_target *, const rar3_batch *, uint64_t *, rar3_progress_cb, void *) {
    fprintf(stderr, "[cuda] backend is a skeleton; port the kernel to enable.\n");
    return -1;
}
}
const rar3_backend *rar3_backend_cuda(void) {
    static rar3_backend be = { "cuda", run_batch, cuda_available };
    return &be;
}
#endif
