#include <stdint.h>
#include <stdio.h>

#include "../../utils.h"
#include "slhvk.h"

int main(void) {
  initTest();

  SlhvkContext ctx;
  int err = slhvkContextInit(&ctx);
  if (err) {
    eprintf("failed to init context: %d\n", err);
    return err;
  }

  // Case 1: zero keys should be rejected.
  err = slhvkKeygenBulk(ctx, 0, NULL, NULL, NULL, NULL);
  if (err != SLHVK_ERROR_INPUT_TOO_LARGE) {
    eprintf("expected error for zero keys, got %d\n", err);
    return 1;
  }

  // Case 2: excessively large key count should be rejected before allocations.
  err = slhvkKeygenBulk(ctx, UINT32_MAX, NULL, NULL, NULL, NULL);
  if (err != SLHVK_ERROR_INPUT_TOO_LARGE) {
    eprintf("expected error for huge key count, got %d\n", err);
    return 1;
  }

  // Case 3: a small, valid keygen still succeeds (smoke test).
  const uint8_t skSeed[SLHVK_N] = {0};
  const uint8_t pkSeed[SLHVK_N] = {0};
  const uint8_t* skSeeds[1] = { skSeed };
  const uint8_t* pkSeeds[1] = { pkSeed };
  uint8_t pkRoot[SLHVK_N];
  uint8_t* pkRoots[1] = { pkRoot };

  err = slhvkKeygenBulk(ctx, 1, skSeeds, pkSeeds, pkRoots, NULL);
  if (err != 0) {
    eprintf("expected success for keysCount=1, got %d\n", err);
    return 1;
  }

  slhvkContextFree(ctx);

  return 0;
}
