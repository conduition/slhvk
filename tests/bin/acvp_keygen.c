#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "../utils.h"
#include "../acvp.h"
#include "slhvk.h"

void eprintHex(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    eprintf("%02x", data[i]);
  }
}

int main() {
  initTest();

  SlhvkContext ctx;
  int err = slhvkContextInit(&ctx);
  if (err) {
    eprintf("failed to init context: %d\n", err);
    return err;
  }

  KeygenTestCase* testCases = NULL;
  int testCasesCount = 0;
  err = readKeygenTestVectors(&testCases, &testCasesCount);
  if (err) {
    eprintf("failed to read keygen test vectors: %d\n", err);
    slhvkContextFree(ctx);
    return err;
  }

  const uint8_t** skSeeds = malloc(testCasesCount * sizeof(uint8_t*));
  const uint8_t** pkSeeds = malloc(testCasesCount * sizeof(uint8_t*));
  uint8_t** pkRoots = malloc(testCasesCount * sizeof(uint8_t*));
  uint8_t* pkRootsBacking = malloc(testCasesCount * SLHVK_N);

  for (int i = 0; i < testCasesCount; i++) {
    skSeeds[i] = &testCases[i].skSeed[0];
    pkSeeds[i] = &testCases[i].pkSeed[0];
    pkRoots[i] = &pkRootsBacking[i * SLHVK_N];
  }


  Time start, end;
  getTime(&start);
  err = slhvkKeygen(ctx, testCasesCount, skSeeds, pkSeeds, pkRoots);
  if (err) {
    eprintf("failed to run keygen: %d\n", err);
    goto cleanup;
  }
  getTime(&end);

  printf("computed %d pk roots in %.2f ms\n", testCasesCount, timeDeltaMillis(start, end));

  for (int i = 0; i < testCasesCount; i++) {
    if (memcmp(testCases[i].pkRoot, pkRoots[i], SLHVK_N) != 0) {
      eprintf("computed incorrect pkRoot!");
      eprintf("test case ID: %d\n", testCases[i].id);
      eprintf("skSeed: ");
      eprintHex(testCases[i].skSeed, SLHVK_N);
      eprintf("\n");
      eprintf("pkSeed: ");
      eprintHex(testCases[i].pkSeed, SLHVK_N);
      eprintf("\n");
      eprintf("computed pkRoot: ");
      eprintHex(pkRoots[i], SLHVK_N);
      eprintf("\n");
      eprintf("expected pkRoot: ");
      eprintHex(testCases[i].pkRoot, SLHVK_N);
      eprintf("\n\n");
      err = -1;
      goto cleanup;
    }
  }

cleanup:
  slhvkContextFree(ctx);
  free(testCases);
  free(skSeeds);
  free(pkSeeds);
  free(pkRoots);
  free(pkRootsBacking);

  return err;
}
