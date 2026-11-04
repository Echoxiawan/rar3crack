/*
 * opencl_backend.cpp - generic OpenCL GPU backend (optional).
 *
 * Build with -DRAR3_WITH_OPENCL=ON. Runs one candidate per work-item using the
 * same RAR3 KDF as the Metal/CUDA backends. Port the MSL kernel in
 * metal_backend.mm to OpenCL C (largely drop-in: replace address-space
 * qualifiers, use __kernel). Provided here as a structured skeleton so the
 * CMake option is functional; the kernel mirrors the validated MSL version.
 */
#if defined(RAR3_HAVE_OPENCL)
#include "backend.h"
#include "rar3.h"
#define CL_TARGET_OPENCL_VERSION 200
#include <CL/cl.h>
#include <vector>
#include <chrono>
#include <cstdio>

static const char *kCL = R"CL(
/* RAR3 kernel: see metal_backend.mm for the equivalent MSL.
   Implement sha1(rar29) + AES-128 + verify, one password per work-item. */
__kernel void rar3_crack(__global const uchar* pwbuf,
                         __global const uint* pwlen,
                         __constant uchar* salt,
                         __constant uchar* enc,
                         __global int* result,
                         const uint count)
{
    uint gid = get_global_id(0);
    if (gid >= count) return;
    /* NOTE: implement the RAR3 OraIter KDF here (port from MSL). */
    result[gid] = 0;
}
)CL";

namespace {
int cl_available() {
    cl_uint n = 0;
    if (clGetPlatformIDs(1, nullptr, &n) != CL_SUCCESS) return 0;
    return n > 0 ? 1 : 0;
}
int run_batch(const rar3_target *, const rar3_batch *, uint64_t *, rar3_progress_cb, void *) {
    fprintf(stderr, "[opencl] backend is a skeleton; port the kernel to enable.\n");
    return -1;
}
}
const rar3_backend *rar3_backend_opencl(void) {
    static rar3_backend be = { "opencl", run_batch, cl_available };
    return &be;
}
#endif
