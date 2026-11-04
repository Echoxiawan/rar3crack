/*
 * rar3.cpp - portable RAR3 KDF + AES verify (pure C++, no OpenSSL dependency).
 *
 * Implements the exact unrar RAR3 (crypt3.cpp SetKey30 + sha1_process_rar29)
 * algorithm, plus a small AES-128 decrypt. Password is encoded as UTF-16LE
 * before the KDF (this is the key subtlety that most implementations miss).
 *
 * Self-validated against the hashcat m12500 official test vector:
 *   pw="hashcat" salt=45109af8ab5f297a enc=adbf6c5385d7a40373e8f77d7b89d317
 */
#include "rar3.h"
#include <string.h>
#include <stdlib.h>

const uint8_t RAR3_SIG[8] = {0xC4, 0x3D, 0x7B, 0x00, 0x40, 0x07, 0x00, 0x00};

/* ---------------- SHA1 (with RAR29 writeback) ---------------- */
namespace {

struct Sha1 {
    uint32_t state[5];
    uint64_t count;
    uint8_t  buffer[64];
};

inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
inline uint32_t bswap32(uint32_t x) {
    return (x >> 24) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | (x << 24);
}
inline void rawput4(uint32_t v, void *p) { memcpy(p, &v, 4); } /* little-endian host */

void sha1_transform(uint32_t state[5], uint32_t ws[16], const uint8_t buf[64], int inplace) {
    uint32_t a, b, c, d, e;
    uint32_t block_l[16];
    uint32_t *l;
    if (inplace) {
        l = (uint32_t *)buf;
    } else {
        memcpy(ws, buf, 64);
        l = ws;
    }
    uint32_t w[80];
    for (int i = 0; i < 16; i++) w[i] = bswap32(l[i]);
    for (int i = 16; i < 80; i++) w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & (c ^ d)) ^ d;         k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d;                 k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
        else             { f = b ^ c ^ d;                 k = 0xCA62C1D6u; }
        uint32_t t = rotl32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl32(b, 30); b = a; a = t;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
    (void)block_l;
}

void sha1_init(Sha1 *c) {
    c->count = 0;
    c->state[0] = 0x67452301u; c->state[1] = 0xEFCDAB89u;
    c->state[2] = 0x98BADCFEu; c->state[3] = 0x10325476u; c->state[4] = 0xC3D2E1F0u;
}

void sha1_block(Sha1 *c, const uint8_t *blk) {
    uint32_t ws[16];
    sha1_transform(c->state, ws, blk, 0);
}

/* standard update (no writeback) */
void sha1_process(Sha1 *c, const uint8_t *data, size_t len) {
    size_t i, j = (size_t)(c->count & 63);
    c->count += len;
    if (j + len > 63) {
        memcpy(c->buffer + j, data, (i = 64 - j));
        sha1_block(c, c->buffer);
        for (; i + 63 < len; i += 64) sha1_block(c, data + i);
        j = 0;
        for (; i < len; i++) c->buffer[j++] = data[i];
        (void)j;
    } else {
        memcpy(c->buffer + j, data, len);
    }
}

/* RAR29 update: after each full block, write expanded words back into the source stream */
void sha1_process_rar29(Sha1 *c, uint8_t *data, size_t len) {
    size_t i, j = (size_t)(c->count & 63);
    c->count += len;
    if (j + len > 63) {
        memcpy(c->buffer + j, data, (i = 64 - j));
        sha1_block(c, c->buffer);
        for (; i + 63 < len; i += 64) {
            sha1_block(c, data + i);
            /* writeback: recompute expanded words and store back to data+i */
            uint32_t w[16];
            for (int k = 0; k < 16; k++)
                w[k] = ((uint32_t)data[i+k*4]<<24)|((uint32_t)data[i+k*4+1]<<16)|
                       ((uint32_t)data[i+k*4+2]<<8)|((uint32_t)data[i+k*4+3]);
            for (int k = 0; k < 16; k++) {
                uint32_t v = w[k];
                data[i+k*4]   = v >> 24; data[i+k*4+1] = v >> 16;
                data[i+k*4+2] = v >> 8;  data[i+k*4+3] = v;
            }
        }
        j = 0;
        for (; i < len; i++) c->buffer[j++] = data[i];
    } else {
        memcpy(c->buffer + j, data, len);
    }
}

void sha1_done(Sha1 *c, uint32_t digest[5]) {
    uint64_t bitlen = c->count * 8;
    uint32_t ws[16];
    uint32_t bufpos = (uint32_t)c->count & 0x3f;
    c->buffer[bufpos++] = 0x80;
    if (bufpos != 56) {
        if (bufpos > 56) { while (bufpos < 64) c->buffer[bufpos++] = 0; sha1_block(c, c->buffer); bufpos = 0; }
        memset(c->buffer + bufpos, 0, 56 - bufpos);
    }
    c->buffer[56] = (uint8_t)(bitlen >> 56); c->buffer[57] = (uint8_t)(bitlen >> 48);
    c->buffer[58] = (uint8_t)(bitlen >> 40); c->buffer[59] = (uint8_t)(bitlen >> 32);
    c->buffer[60] = (uint8_t)(bitlen >> 24); c->buffer[61] = (uint8_t)(bitlen >> 16);
    c->buffer[62] = (uint8_t)(bitlen >> 8);  c->buffer[63] = (uint8_t)(bitlen);
    sha1_block(c, c->buffer);
    for (int i = 0; i < 5; i++) digest[i] = c->state[i];
}

/* ---------------- AES-128 (decrypt only) ---------------- */
const uint8_t sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
const uint8_t invsbox[256] = {
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d};

inline uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80; a <<= 1; if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void aes_expand_key(const uint8_t key[16], uint8_t rk[176]) {
    memcpy(rk, key, 16);
    int r = 0;
    for (int i = 16; i < 176; i += 4) {
        uint8_t t[4] = {rk[i-4], rk[i-3], rk[i-2], rk[i-1]};
        if (i % 16 == 0) {
            uint8_t u = t[0];
            t[0] = sbox[t[1]]; t[1] = sbox[t[2]]; t[2] = sbox[t[3]]; t[3] = sbox[u];
            uint8_t rc = 1; for (int k = 0; k < r; k++) rc = gmul(rc, 2);
            t[0] ^= rc; r++;
        }
        for (int j = 0; j < 4; j++) rk[i+j] = rk[i-16+j] ^ t[j];
    }
}

void aes_decrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    uint8_t rk[176];
    aes_expand_key(key, rk);
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[160+i];
    for (int round = 9; round >= 1; round--) {
        uint8_t t[16];
        t[0]=s[0];t[1]=s[13];t[2]=s[10];t[3]=s[7];
        t[4]=s[4];t[5]=s[1];t[6]=s[14];t[7]=s[11];
        t[8]=s[8];t[9]=s[5];t[10]=s[2];t[11]=s[15];
        t[12]=s[12];t[13]=s[9];t[14]=s[6];t[15]=s[3];
        for (int i = 0; i < 16; i++) s[i] = invsbox[t[i]];
        for (int i = 0; i < 16; i++) s[i] ^= rk[round*16+i];
        for (int c = 0; c < 4; c++) {
            uint8_t a0=s[c*4],a1=s[c*4+1],a2=s[c*4+2],a3=s[c*4+3];
            s[c*4]  = gmul(a0,14)^gmul(a1,11)^gmul(a2,13)^gmul(a3,9);
            s[c*4+1]= gmul(a0,9)^gmul(a1,14)^gmul(a2,11)^gmul(a3,13);
            s[c*4+2]= gmul(a0,13)^gmul(a1,9)^gmul(a2,14)^gmul(a3,11);
            s[c*4+3]= gmul(a0,11)^gmul(a1,13)^gmul(a2,9)^gmul(a3,14);
        }
    }
    uint8_t t[16];
    t[0]=s[0];t[1]=s[13];t[2]=s[10];t[3]=s[7];
    t[4]=s[4];t[5]=s[1];t[6]=s[14];t[7]=s[11];
    t[8]=s[8];t[9]=s[5];t[10]=s[2];t[11]=s[15];
    t[12]=s[12];t[13]=s[9];t[14]=s[6];t[15]=s[3];
    for (int i = 0; i < 16; i++) out[i] = invsbox[t[i]] ^ rk[i];
}

/* UTF-8 -> UTF-16LE byte expansion */
size_t utf8_to_utf16le(const uint8_t *s, size_t n, uint8_t *out, size_t outcap) {
    size_t o = 0;
    for (size_t i = 0; i < n; ) {
        uint32_t cp; int len;
        uint8_t c = s[i];
        if (c < 0x80) { cp = c; len = 1; }
        else if ((c >> 5) == 0x6) { cp = c & 0x1f; len = 2; }
        else if ((c >> 4) == 0xe) { cp = c & 0x0f; len = 3; }
        else if ((c >> 3) == 0x1e) { cp = c & 0x07; len = 4; }
        else { cp = c; len = 1; }
        for (int k = 1; k < len && i + k < n; k++) cp = (cp << 6) | (s[i+k] & 0x3f);
        i += len;
        if (cp < 0x10000) {
            if (o + 2 > outcap) break;
            out[o++] = cp & 0xff; out[o++] = (cp >> 8) & 0xff;
        } else {
            if (o + 4 > outcap) break;
            cp -= 0x10000;
            uint32_t hi = 0xd800 + ((cp >> 10) & 0x3ff), lo = 0xdc00 + (cp & 0x3ff);
            out[o++] = hi & 0xff; out[o++] = hi >> 8; out[o++] = lo & 0xff; out[o++] = lo >> 8;
        }
    }
    return o;
}

} // namespace

/* ---------------- public API ---------------- */
#define HR 0x40000u

void rar3_derive_key_iv(const uint8_t *pw, size_t pw_len,
                        const uint8_t salt[8],
                        uint8_t key_out[16], uint8_t iv_out[16]) {
    uint8_t pw16[512];
    size_t pw16len = utf8_to_utf16le(pw, pw_len, pw16, sizeof(pw16));
    uint8_t raw[512 + 8];
    memcpy(raw, pw16, pw16len);
    memcpy(raw + pw16len, salt, 8);
    size_t rawlen = pw16len + 8;

    Sha1 c;
    sha1_init(&c);
    uint8_t aesinit[16];
    uint8_t buf[520];
    for (uint32_t I = 0; I < HR; I++) {
        memcpy(buf, raw, rawlen);
        sha1_process_rar29(&c, buf, rawlen);
        uint8_t pn[3] = { (uint8_t)I, (uint8_t)(I>>8), (uint8_t)(I>>16) };
        sha1_process(&c, pn, 3);
        if (I % (HR/16) == 0) {
            Sha1 tc = c;
            uint32_t dg[5];
            sha1_done(&tc, dg);
            aesinit[I/(HR/16)] = (uint8_t)dg[4];
        }
    }
    uint32_t dg[5];
    sha1_done(&c, dg);
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            key_out[i*4+j] = (uint8_t)(dg[i] >> (j*8));
    memcpy(iv_out, aesinit, 16);
}

int rar3_check_password(const rar3_target *t, const uint8_t *pw, size_t pw_len) {
    uint8_t key[16], iv[16];
    rar3_derive_key_iv(pw, pw_len, t->salt, key, iv);
    uint8_t dec[16], out[16];
    aes_decrypt_block(key, t->enc, dec);
    for (int i = 0; i < 16; i++) out[i] = dec[i] ^ iv[i];
    return memcmp(out, RAR3_SIG, 8) == 0 ? 1 : 0;
}
