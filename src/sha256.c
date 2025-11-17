#include <string.h>

#include "sha256.h"

#define MIN(x, y) (x < y ? x : y)

const uint32_t SLHVK_SHA256_INITIAL_STATE[8] = SHA256_INITIAL_STATE_DEF;

static const uint32_t K[] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t rotr(uint32_t x, uint32_t n) {
  return (x << (32 - n)) | (x >> n);
}

static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x & (y ^ z)) ^ (y & z);
}

static inline uint32_t ch(uint32_t e, uint32_t f, uint32_t g) {
  return (e & f) ^ ((~e) & g);
}

static inline uint32_t sum0(uint32_t x) {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static inline uint32_t sum1(uint32_t x) {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static inline uint32_t sigma0(uint32_t x) {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static inline uint32_t sigma1(uint32_t x) {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

static inline uint32_t load_u32(const uint8_t* ptr) {
  return ((uint32_t) ptr[0] << 24) |
         ((uint32_t) ptr[1] << 16) |
         ((uint32_t) ptr[2] << 8) |
         ((uint32_t) ptr[3]);
}

static inline void store_u32(uint8_t *x, uint32_t v) {
  x[3] = (uint8_t) v;
  v >>= 8;
  x[2] = (uint8_t) v;
  v >>= 8;
  x[1] = (uint8_t) v;
  v >>= 8;
  x[0] = (uint8_t) v;
}

void slhvkSha256Compress(uint32_t state[8], const uint8_t block[64]) {
  uint32_t schedule[64] = {0};

  for (int i = 0; i < 16; i++) {
    schedule[i] = load_u32(&block[i * 4]);
  }

  for (int t = 16; t < 64; t++) {
    schedule[t] =
      sigma1(schedule[t - 2]) +
      schedule[t - 7] +
      sigma0(schedule[t - 15]) +
      schedule[t - 16];
  }

  uint32_t t1, t2;
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3],
           e = state[4], f = state[5], g = state[6], h = state[7];


  for (int r = 0; r < 64; r++) {
    t1 = h + sum1(e) + ch(e, f, g) + K[r] + schedule[r];
    t2 = sum0(a) + maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  uint32_t output_state[8] = {a, b, c, d, e, f, g, h};
  for (int i = 0; i < 8; i++) {
    state[i] += output_state[i];
  }
}

void slhvkSha256Init(ShaContext* ctx) {
  memcpy(ctx->state, SLHVK_SHA256_INITIAL_STATE, 32);
  memset(ctx->block, 0, 64);
  ctx->ctr = 0;
}

void slhvkSha256Clone(ShaContext* ctx_dest, const ShaContext* ctx_src) {
  memcpy(ctx_dest->state, ctx_src->state, 32);
  memcpy(ctx_dest->block, ctx_src->block, 64);
  ctx_dest->ctr = ctx_src->ctr;
}

void slhvkSha256Update(ShaContext* ctx, const uint8_t* data, size_t data_len) {
  size_t start = ctx->ctr % 64;
  size_t remaining = data_len;
  while (start + remaining >= 64) {
    size_t count = 64 - start;
    memcpy(&ctx->block[start], &data[data_len - remaining], count);
    slhvkSha256Compress(ctx->state, ctx->block);
    ctx->ctr += count;
    remaining -= count;
    start = ctx->ctr % 64;
  }

  memcpy(&ctx->block[start], &data[data_len - remaining], remaining);
  ctx->ctr += remaining;
}

void slhvkSha256Finalize(ShaContext* ctx, uint8_t* output, size_t output_len) {
  size_t pad_start = ctx->ctr % 64;
  memset(&ctx->block[pad_start], 0, 64 - pad_start);
  ctx->block[pad_start] = 0x80;

  size_t total_bit_length = 8 * ctx->ctr;
  if (pad_start >= 56) {
    slhvkSha256Compress(ctx->state, ctx->block);
    memset(ctx->block, 0, 64);
  }

  store_u32(&ctx->block[56], (uint32_t) (total_bit_length >> 32));
  store_u32(&ctx->block[60], (uint32_t) total_bit_length);
  slhvkSha256Compress(ctx->state, ctx->block);

  output_len = MIN(output_len, 32);
  for (size_t i = 0; i < output_len; i++) {
    output[i] = (uint8_t) (ctx->state[i / 4] >> (24 - 8 * (i % 4)));
  }
}
