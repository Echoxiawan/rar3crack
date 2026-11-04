/*
 * selftest.cpp - validate the portable core against hashcat m12500 test vector.
 * pw="hashcat"
 * salt=45109af8ab5f297a
 * enc =adbf6c5385d7a40373e8f77d7b89d317
 */
#include "rar3.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    rar3_target t;
    const uint8_t salt[8] = {0x45,0x10,0x9a,0xf8,0xab,0x5f,0x29,0x7a};
    const uint8_t enc[16] = {0xad,0xbf,0x6c,0x53,0x85,0xd7,0xa4,0x03,
                             0x73,0xe8,0xf7,0x7d,0x7b,0x89,0xd3,0x17};
    memcpy(t.salt, salt, 8);
    memcpy(t.enc, enc, 16);

    const char *good = "hashcat";
    const char *bad  = "hashcaT";

    int r1 = rar3_check_password(&t, (const uint8_t*)good, strlen(good));
    int r2 = rar3_check_password(&t, (const uint8_t*)bad,  strlen(bad));

    printf("[selftest] pw=%-8s -> %s\n", good, r1 == 1 ? "MATCH  (core OK)" : "NO MATCH (BUG)");
    printf("[selftest] pw=%-8s -> %s\n", bad,  r2 == 0 ? "NO MATCH (expected)" : "MATCH (BUG)");

    return (r1 == 1 && r2 == 0) ? 0 : 1;
}
