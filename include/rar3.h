#ifndef RAR3_H
#define RAR3_H
/*
 * rar3.h - RAR3 (RAR v4) archive password recovery - portable core API
 *
 * RAR3 uses a bespoke SHA1-based KDF ("OraIter"): the password (converted to
 * UTF-16LE) is concatenated with the 8-byte salt, then 0x40000 rounds of
 * SHA1 with a 3-byte little-endian counter are chained. The final digest yields
 * a 16-byte AES-128 key and a 16-byte IV sampled every (0x40000/16) rounds.
 * Verification decrypts the first 16 encrypted header bytes and checks the
 * RAR3 header signature C4 3D 7B 00 40 07 00 00.
 */
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Fixed verification target: first 8 bytes of the decrypted header. */
extern const uint8_t RAR3_SIG[8];

typedef struct {
    uint8_t salt[8];    /* KDF salt (little-endian as stored) */
    uint8_t enc[16];    /* first 16 encrypted header bytes */
} rar3_target;

/*
 * Core: given a raw password (bytes; converted to UTF-16LE internally),
 * compute AES key+iv and verify against *t*.
 * Returns 1 on match, 0 on no match, -1 on internal error.
 */
int rar3_check_password(const rar3_target *t,
                        const uint8_t *pw, size_t pw_len);

/*
 * Batch-friendly variant: fills key(16) and iv(16) for a password.
 * (Used by GPU backends for self-testing / cross-checking.)
 */
void rar3_derive_key_iv(const uint8_t *pw, size_t pw_len,
                        const uint8_t salt[8],
                        uint8_t key_out[16], uint8_t iv_out[16]);

#ifdef __cplusplus
}
#endif
#endif /* RAR3_H */
