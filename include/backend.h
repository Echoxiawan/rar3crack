#ifndef BACKEND_H
#define BACKEND_H
/*
 * backend.h - abstract attack backend interface.
 *
 * Every backend (CPU, Metal, CUDA, OpenCL) implements the same contract:
 * given a list of candidate passwords, find the one matching the target and
 * report progress through a callback.
 */
#include <stdint.h>
#include <stddef.h>
#include "rar3.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Return 1 to continue, 0 to stop (found / cancelled). */
typedef int (*rar3_progress_cb)(void *user,
                                uint64_t tried, uint64_t total,
                                double elapsed_sec);

/* A batch of candidates: fixed 16-byte ASCII slots + lengths. */
typedef struct {
    const uint8_t (*pw)[16];  /* count * 16 */
    const uint8_t *pwlen;     /* count bytes */
    uint64_t count;
} rar3_batch;

typedef struct {
    const char *name;
    /* run a batch; on match set *match_index and return 1. returns 0 done-no-match, <0 error. */
    int (*run_batch)(const rar3_target *t, const rar3_batch *b,
                     uint64_t *match_index, rar3_progress_cb cb, void *user);
    int (*available)(void);   /* 1 if usable on this machine */
} rar3_backend;

/* Implemented per-platform in backends/. */
const rar3_backend *rar3_backend_cpu(void);
const rar3_backend *rar3_backend_metal(void);   /* macOS only; returns NULL elsewhere */
const rar3_backend *rar3_backend_opencl(void);  /* generic; may be NULL */
const rar3_backend *rar3_backend_cuda(void);    /* NVIDIA; may be NULL */

#ifdef __cplusplus
}
#endif
#endif
