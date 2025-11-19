#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "../../utils.h"
#include "slhvk.h"

int main() {
  initTest();

  Time initStart, initEnd;
  getTime(&initStart);

  SlhvkContext ctx;
  int err = slhvkContextInit(&ctx);
  if (err) {
    eprintf("failed to init context: %d\n", err);
    return err;
  }
  getTime(&initEnd);
  printf("initialized SLHVK context in %.2f ms\n", timeDeltaMillis(initStart, initEnd));

  uint8_t pkSeed[SLHVK_N] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
  uint8_t skSeed[SLHVK_N] = {0x00, 0x00, 0x11, 0x22, 0xff, 0x29, 0x99, 0x90,
                             0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd};

  #define KEYGEN_RUNS 512
  const uint8_t* skSeeds[KEYGEN_RUNS];
  const uint8_t* pkSeeds[KEYGEN_RUNS];
  uint8_t pkRoots[KEYGEN_RUNS][SLHVK_N];
  uint8_t cachedRootTree[SLHVK_XMSS_CACHED_TREE_SIZE];
  uint8_t* pkRootsPtr[KEYGEN_RUNS];
  uint8_t* cachedRootTreesPtr[KEYGEN_RUNS];

  for (int i = 0; i < KEYGEN_RUNS; i++) {
    skSeeds[i] = skSeed;
    pkSeeds[i] = pkSeed;
    pkRootsPtr[i] = pkRoots[i];
    cachedRootTreesPtr[i] = cachedRootTree;
  }

  int nRuns = 0;
  Time start, end;
  getTime(&start);
  do {
    err = slhvkKeygenBulk(ctx, KEYGEN_RUNS, skSeeds, pkSeeds, pkRootsPtr, cachedRootTreesPtr);
    if (err) {
      eprintf("failed to run keygen: %d\n", err);
      goto cleanup;
    }
    nRuns += KEYGEN_RUNS;
    getTime(&end);
  } while (timeDeltaMillis(start, end) < 5000.0);

  printf("took %.2f ms per key gen\n", timeDeltaMillis(start, end) / (double) nRuns);


cleanup:
  slhvkContextFree(ctx);

  return err;
}
