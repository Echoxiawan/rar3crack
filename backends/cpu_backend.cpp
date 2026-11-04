/*
 * cpu_backend.cpp - multi-threaded CPU backend using the portable core.
 * Runs on every platform; always available. Zero external deps.
 */
#include "backend.h"
#include "rar3.h"
#include <thread>
#include <atomic>
#include <vector>
#include <chrono>

namespace {

struct Ctx {
    const rar3_target *t;
    const rar3_batch *b;
    std::atomic<uint64_t> idx;
    std::atomic<int> found;
    std::atomic<uint64_t> hitidx;
    std::atomic<uint64_t> done;
};

void worker(Ctx *c) {
    for (;;) {
        if (c->found.load(std::memory_order_relaxed)) return;
        uint64_t k = c->idx.fetch_add(1, std::memory_order_relaxed);
        if (k >= c->b->count) return;
        const uint8_t *pw = c->b->pw[k];
        uint8_t len = c->b->pwlen[k];
        if (rar3_check_password(c->t, pw, len) == 1) {
            if (!c->found.exchange(1)) c->hitidx.store(k);
            return;
        }
        c->done.fetch_add(1, std::memory_order_relaxed);
    }
}

int run_batch(const rar3_target *t, const rar3_batch *b,
              uint64_t *match_index, rar3_progress_cb cb, void *user) {
    Ctx c;
    c.t = t; c.b = b;
    c.idx.store(0); c.found.store(0); c.done.store(0); c.hitidx.store(0);

    unsigned nthreads = std::thread::hardware_concurrency();
    if (nthreads == 0) nthreads = 4;
    if (nthreads > 64) nthreads = 64;

    auto t0 = std::chrono::steady_clock::now();
    std::vector<std::thread> th;
    for (unsigned i = 0; i < nthreads; i++) th.emplace_back(worker, &c);

    /* progress reporter */
    bool stop_report = false;
    std::thread reporter([&]{
        while (!stop_report) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            if (stop_report) break;
            double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            if (cb && !cb(user, c.done.load(), b->count, el)) {
                c.found.store(1); /* signal stop */
                break;
            }
        }
    });

    for (auto &x : th) x.join();
    stop_report = true;
    reporter.join();

    if (c.found.load() && c.done.load() < b->count) {
        /* Report final */
        double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        if (cb) cb(user, c.done.load(), b->count, el);
        *match_index = c.hitidx.load();
        return 1;
    }
    double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (cb) cb(user, c.done.load(), b->count, el);
    return 0;
}

int available(void) { return 1; }
const rar3_backend g_cpu = { "cpu", run_batch, available };

} // namespace

const rar3_backend *rar3_backend_cpu(void) { return &g_cpu; }
