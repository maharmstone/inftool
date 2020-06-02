/* ================ sha1.h ================ */
/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#pragma once

#include <stdint.h>

typedef struct {
    uint32_t state[5];
    size_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, const void* data, size_t len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);