#pragma once
#include <stdint.h>
#include <stddef.h>

extern const uint32_t SHA256_INITIAL_STATE[8];

#define SHA256_INITIAL_STATE_DEF { \
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, \
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, \
}

typedef struct ShaContext {
  uint32_t state[8];
  uint8_t  block[64];
  size_t   ctr;
} ShaContext;

void sha256_init(ShaContext* ctx);
void sha256_clone(ShaContext* ctx_dest, const ShaContext* ctx_src);
void sha256_compress(uint32_t state[8], const uint8_t block[64]);
void sha256_update(ShaContext* ctx, const uint8_t* data, size_t data_len);
void sha256_finalize(ShaContext* ctx, uint8_t* output, size_t output_len);
