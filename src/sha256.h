#pragma once
#include <stdint.h>

extern const uint32_t SLHVK_SHA256_INITIAL_STATE[8];

#define SHA256_INITIAL_STATE_DEF { \
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, \
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, \
}

typedef struct ShaContext {
  uint32_t state[8];
  uint8_t  block[64];
  size_t   ctr;
} ShaContext;

void slhvkSha256Init(ShaContext* ctx);
void slhvkSha256Clone(ShaContext* ctx_dest, const ShaContext* ctx_src);
void slhvkSha256Compress(uint32_t state[8], const uint8_t block[64]);
void slhvkSha256Update(ShaContext* ctx, const uint8_t* data, size_t data_len);
void slhvkSha256Finalize(ShaContext* ctx, uint8_t* output, size_t output_len);
