/*
 * main.cpp - rar3crack CLI
 *
 * Usage:
 *   rar3crack <archive.rar> [options]
 * Options:
 *   -w, --wordlist FILE     dictionary file (one candidate per line)
 *   -d, --digits N          brute-force N-digit numbers (first digit 1-9)
 *   -c, --charset SET       custom charset brute force (advanced)
 *   -b, --backend NAME      cpu|metal|opencl|cuda|auto (default: auto)
 *   -t, --threads N         CPU threads (default: auto)
 *       --extract-hash      print target salt/enc and exit
 *   -q, --quiet             less output
 *
 * Auto backend order: metal (macOS) > cuda > opencl > cpu
 */
#include "backend.h"
#include "rar3.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>

#if defined(__APPLE__)
#endif

/* ---------------- RAR parsing: extract salt + first encrypted header bytes ---------------- */
struct RarTarget {
    rar3_target t;
    bool ok = false;
    uint64_t packsize = 0, unpsize = 0;
    std::string name;
};

static uint32_t rd16(const uint8_t *p){ return p[0] | (p[1]<<8); }
static uint32_t rd32(const uint8_t *p){ return p[0] | (p[1]<<8) | (p[2]<<16) | ((uint32_t)p[3]<<24); }

/* Parse a RAR3 (v4) archive; extract salt + first 16 encrypted header bytes. */
static RarTarget parse_rar3(const char *path, bool verbose) {
    RarTarget r;
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "error: cannot open %s\n", path); return r; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> d(sz);
    if (fread(d.data(), 1, sz, f) != (size_t)sz) { fclose(f); fprintf(stderr,"error: read failed\n"); return r; }
    fclose(f);

    if (sz < 14 || memcmp(d.data(), "\x52\x61\x72\x21\x1a\x07\x00", 7) != 0) {
        fprintf(stderr, "error: not a RAR4 archive\n"); return r;
    }
    size_t i = 7;
    int guard = 0;
    while (i + 7 <= (size_t)sz && guard++ < 4096) {
        uint8_t type = d[i+2];
        uint16_t flags = rd16(&d[i+3]);
        uint16_t hsize = rd16(&d[i+5]);
        if (hsize < 7) break;
        if (type == 0x73) { /* archive header */
            i += hsize; continue;
        }
        if (type == 0x74) { /* file header */
            uint32_t packsize = rd32(&d[i+7]);
            size_t p = i + 7;
            p += 4;                       /* packsize */
            uint32_t unp = rd32(&d[p]); p += 4; (void)unp;
            p += 1;                       /* hostos */
            p += 4;                       /* fcrc */
            p += 4;                       /* ftime */
            p += 1;                       /* unpver */
            p += 1;                       /* method */
            uint16_t namelen = rd16(&d[p]); p += 2;
            p += 4;                       /* attr */
            std::string name((const char*)&d[p], namelen); p += namelen;
            if (!(flags & 0x0004) && !(flags & 0x0080)) { /* not password-encrypted */
                fprintf(stderr, "warning: file '%s' is not encrypted\n", name.c_str());
            }
            if (p + 8 + 16 > (size_t)sz) break;
            uint8_t salt[8]; memcpy(salt, &d[p], 8); p += 8;
            p += 16; /* IV */
            if (p + 16 > (size_t)sz) break;
            memcpy(r.t.salt, salt, 8);
            memcpy(r.t.enc, &d[p], 16);
            r.packsize = packsize; r.unpsize = unp;
            r.name = name;
            r.ok = true;
            if (verbose) {
                fprintf(stderr, "[i] file: %s  packed=%u unpacked=%u\n", name.c_str(), packsize, unp);
                fprintf(stderr, "[i] salt=");
                for (int k=0;k<8;k++) fprintf(stderr,"%02x",salt[k]);
                fprintf(stderr,"  enc16=");
                for (int k=0;k<16;k++) fprintf(stderr,"%02x",r.t.enc[k]);
                fprintf(stderr,"\n");
            }
            return r;
        }
        if (type == 0x7a) break; /* end of archive */
        /* otherwise skip block */
        uint32_t pack = 0;
        if (type == 0x74) pack = rd32(&d[i+7]);
        i += hsize + pack;
    }
    fprintf(stderr, "error: no encrypted file header found\n");
    return r;
}

/* ---------------- candidate generation ---------------- */
struct Batch {
    std::vector<uint8_t> pw;   /* count*16 ASCII */
    std::vector<uint8_t> len;  /* count */
    void add(const char *s, size_t n) {
        if (n > 16) n = 16;
        uint8_t buf[16]; memset(buf,0,16); memcpy(buf,s,n);
        pw.insert(pw.end(), buf, buf+16);
        len.push_back((uint8_t)n);
    }
    uint64_t count() const { return len.size(); }
    rar3_batch batch() const {
        rar3_batch b; b.pw = (const uint8_t(*)[16])pw.data(); b.pwlen = len.data(); b.count = count();
        return b;
    }
};

static bool load_wordlist(const char *path, Batch &out) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr,"error: cannot open wordlist %s\n", path); return false; }
    char line[512];
    while (fgets(line, sizeof line, f)) {
        size_t L = strlen(line);
        while (L && (line[L-1]=='\n' || line[L-1]=='\r')) line[--L]=0;
        if (L == 0) continue;
        out.add(line, L);
    }
    fclose(f);
    return true;
}

static void gen_digits(int n, Batch &out) {
    if (n < 1 || n > 12) { fprintf(stderr,"error: digits must be 1..12\n"); return; }
    uint64_t lo = 1, hi = 9;
    for (int i = 1; i < n; i++) { lo *= 10; hi = hi*10 + 9; }
    char buf[32];
    for (uint64_t v = lo; v <= hi; v++) {
        int L = snprintf(buf, sizeof buf, "%llu", (unsigned long long)v);
        out.add(buf, L);
    }
}

/* ---------------- progress printer ---------------- */
static int progress_cb(void *user, uint64_t tried, uint64_t total, double el) {
    bool *quiet = (bool*)user;
    double rate = el > 0 ? tried / el : 0;
    if (!*quiet) {
        double pct = total ? (100.0 * tried / total) : 0;
        fprintf(stderr, "\r[%.2f%%] %llu/%llu  %.0f/s", pct,
                (unsigned long long)tried, (unsigned long long)total, rate);
        if (tried >= total) fprintf(stderr, "\n");
    }
    return 1;
}

/* ---------------- backend selection ---------------- */
static const rar3_backend *pick_backend(const char *want) {
    if (!want || !strcmp(want, "auto")) {
        const rar3_backend *cands[] = {
            rar3_backend_metal(), rar3_backend_cuda(),
            rar3_backend_opencl(), rar3_backend_cpu(), nullptr
        };
        for (int i = 0; cands[i]; i++)
            if (cands[i]->available()) return cands[i];
        return rar3_backend_cpu();
    }
    if (!strcmp(want,"cpu"))    return rar3_backend_cpu();
    if (!strcmp(want,"metal"))  return rar3_backend_metal();
    if (!strcmp(want,"cuda"))   return rar3_backend_cuda();
    if (!strcmp(want,"opencl")) return rar3_backend_opencl();
    return rar3_backend_cpu();
}

static void usage(const char *prog) {
    fprintf(stderr,
        "rar3crack - RAR3 (RAR v4) password recovery\n\n"
        "Usage: %s <archive.rar> [options]\n\n"
        "Options:\n"
        "  -w, --wordlist FILE   dictionary file (one candidate per line)\n"
        "  -d, --digits N        brute-force N-digit numbers (first digit 1-9)\n"
        "  -b, --backend NAME    cpu|metal|opencl|cuda|auto (default: auto)\n"
        "  -t, --threads N       CPU worker threads (default: auto)\n"
        "      --extract-hash    print salt/enc target and exit\n"
        "  -q, --quiet           quieter output\n"
        "  -h, --help            show help\n", prog);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 2; }
    const char *archive = nullptr;
    const char *wordlist = nullptr;
    int digits = -1;
    const char *backend = "auto";
    bool quiet = false, extract = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a,"-w")||!strcmp(a,"--wordlist")) wordlist = argv[++i];
        else if (!strcmp(a,"-d")||!strcmp(a,"--digits")) digits = atoi(argv[++i]);
        else if (!strcmp(a,"-b")||!strcmp(a,"--backend")) backend = argv[++i];
        else if (!strcmp(a,"-t")||!strcmp(a,"--threads")) { ++i; /* consumed by cpu backend via env */ }
        else if (!strcmp(a,"--extract-hash")) extract = true;
        else if (!strcmp(a,"-q")||!strcmp(a,"--quiet")) quiet = true;
        else if (!strcmp(a,"-h")||!strcmp(a,"--help")) { usage(argv[0]); return 0; }
        else if (a[0] != '-') archive = a;
        else { fprintf(stderr,"unknown option %s\n", a); usage(argv[0]); return 2; }
    }
    if (!archive) { fprintf(stderr,"error: specify archive.rar\n"); return 2; }

    RarTarget rt = parse_rar3(archive, !quiet);
    if (!rt.ok) return 1;

    if (extract) {
        printf("salt=");
        for (int k=0;k<8;k++) printf("%02x", rt.t.salt[k]);
        printf("\nenc16=");
        for (int k=0;k<16;k++) printf("%02x", rt.t.enc[k]);
        printf("\nfile=%s\n", rt.name.c_str());
        return 0;
    }

    if (!wordlist && digits < 0) {
        fprintf(stderr,"error: need -w wordlist or -d digits\n");
        return 2;
    }

    Batch cands;
    if (wordlist) { if (!load_wordlist(wordlist, cands)) return 1; }
    if (digits > 0) gen_digits(digits, cands);

    if (cands.count() == 0) { fprintf(stderr,"error: no candidates\n"); return 1; }

    const rar3_backend *be = pick_backend(backend);
    if (!be) be = rar3_backend_cpu();
    if (!be->available()) {
        fprintf(stderr,"[!] backend '%s' unavailable, falling back to cpu\n", be->name);
        be = rar3_backend_cpu();
    }

    if (!quiet) fprintf(stderr,"[*] archive: %s\n[*] backend: %s\n[*] candidates: %llu\n",
                        archive, be->name, (unsigned long long)cands.count());

    uint64_t hit = 0;
    rar3_batch b = cands.batch();
    int rc = be->run_batch(&rt.t, &b, &hit, progress_cb, &quiet);

    if (rc == 1) {
        /* recover the password text from batch */
        const uint8_t *p = cands.pw.data() + hit*16;
        size_t L = cands.len[hit];
        printf("*** FOUND: %.*s ***\n", (int)L, (const char*)p);
        return 0;
    } else if (rc == 0) {
        printf("not found (%llu candidates)\n", (unsigned long long)cands.count());
        return 1;
    }
    fprintf(stderr,"error: backend failed\n");
    return 2;
}
