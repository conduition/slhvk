#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "../utils.h"
#include "context.h"

int main() {
  init_test();

  SlhvkContext ctx;
  int err = slhvkContextInit(&ctx);
  if (err) {
    eprintf("failed to init context: %d\n", err);
    return err;
  }

  uint8_t pkSeed[SLHVK_N] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
  uint8_t pkRoot[SLHVK_N] = {0};
  uint8_t skPrf[SLHVK_N] = {0};
  uint8_t skSeed[SLHVK_N] = {0x00, 0x00, 0x11, 0x22, 0xff, 0x29, 0x99, 0x90,
                             0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd};
  const uint8_t message[] = "hello world";

  uint8_t slhDsaSignature[SLHVK_SIGNATURE_SIZE];

  const uint8_t contextString[] = "string";
  const uint8_t addrnd[] = {5, 4, 3, 2, 1, 0, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

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
    eprintf("failed to run context: %d\n", err);
    goto cleanup;
  }

cleanup:
  slhvkContextFree(ctx);

  return err;
}
