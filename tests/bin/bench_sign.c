#include <stdint.h>
#include <stdio.h>

#include "../utils.h"
#include "slhvk.h"

int main() {
  initTest();

  SlhvkContext ctx;
  int err = slhvkContextInit(&ctx);
  if (err) {
    eprintf("failed to init context: %d\n", err);
    return err;
  }

  uint8_t pkSeed[SLHVK_N] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
  uint8_t skPrf[SLHVK_N] = {0};
  uint8_t skSeed[SLHVK_N] = {0x00, 0x00, 0x11, 0x22, 0xff, 0x29, 0x99, 0x90,
                             0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd};
  uint8_t pkRoot[SLHVK_N] = {0x8f, 0x0c, 0x8e, 0xe4, 0xaf, 0xdf, 0xc4, 0x64,
                             0x61, 0x75, 0xc8, 0x35, 0x1e, 0x17, 0x6a, 0x2f};

  const uint8_t message[] = "hello world";
  const uint8_t contextString[] = "string";
  const uint8_t addrnd[] = {5, 4, 3, 2, 1, 0, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

  uint8_t slhDsaSignature[SLHVK_SIGNATURE_SIZE];

  int nRuns = 0;
  Time start, end;
  getTime(&start);
  #define SIGNING_RUNS 100
  do {
    for (int i = 0; i < SIGNING_RUNS; i++) {
      err = slhvkSignPure(
        ctx,
        skSeed,
        skPrf,
        pkSeed,
        pkRoot,
        addrnd,
        contextString,
        sizeof(contextString) - 1, // minus 1 for null terminator
        message,
        sizeof(message) - 1, // minus 1 for null terminator
        slhDsaSignature
      );
      if (err) {
        eprintf("failed to run signing: %d\n", err);
        goto cleanup;
      }
    }
    nRuns += SIGNING_RUNS;
    getTime(&end);
  } while (timeDeltaMillis(start, end) < 5000.0);

  // for (int i = 0; i < SLHVK_SIGNATURE_SIZE; i++)
  //   printf("%02x", slhDsaSignature[i]);
  // printf("\n");

  printf("took %.2f ms per signature\n", timeDeltaMillis(start, end) / (double) nRuns);

cleanup:
  slhvkContextFree(ctx);

  return err;
}
