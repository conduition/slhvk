#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "../utils.h"
#include "slhvk.h"

int main() {
  init_test();

  SlhvkContext ctx;
  int err = slhvkContextInit(&ctx);
  if (err) {
    eprintf("failed to init context: %d\n", err);
    return err;
  }

  uint8_t pkSeed[SLHVK_N] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
  uint8_t skSeed[SLHVK_N] = {0x00, 0x00, 0x11, 0x22, 0xff, 0x29, 0x99, 0x90,
                             0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd};
  uint8_t pkRoot[SLHVK_N] = {0};


  #define KEYGEN_RUNS 512
  const uint8_t* skSeeds[KEYGEN_RUNS];
  const uint8_t* pkSeeds[KEYGEN_RUNS];
  uint8_t pkRoots[KEYGEN_RUNS][SLHVK_N];
  uint8_t* pkRootsPtr[KEYGEN_RUNS];

  for (int i = 0; i < KEYGEN_RUNS; i++) {
    skSeeds[i] = skSeed;
    pkSeeds[i] = pkSeed;
    pkRootsPtr[i] = &pkRoots[i][0];
  }

  int nRuns = 0;
  Time start, end;
  get_time(&start);
  do {
    err = slhvkKeygen(ctx, KEYGEN_RUNS, skSeeds, pkSeeds, pkRootsPtr);
    if (err) {
      eprintf("failed to run keygen: %d\n", err);
      goto cleanup;
    }
    nRuns += KEYGEN_RUNS;
    get_time(&end);
  } while (time_delta_ms(start, end) < 5000.0);

  printf("took %.2f ms per key gen\n", time_delta_ms(start, end) / (double) nRuns);

  memcpy(pkRoot, pkRoots[0], SLHVK_N);
  printf("generated pk_root: ");
  for (int j = 0; j < SLHVK_N; j++)
    printf("%02x", pkRoot[j]);
  printf("\n");


cleanup:
  slhvkContextFree(ctx);

  return err;
}
