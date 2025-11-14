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
  init_test();

  SlhvkContext ctx;
  int err = slhvkContextInit(&ctx);
  if (err) {
    eprintf("failed to init context: %d\n", err);
    return err;
  }

  SigningTestCase* testCases = NULL;
  int testCasesCount = 0;
  err = readSigningTestVectors(&testCases, &testCasesCount);
  if (err) {
    eprintf("failed to read signing test vectors: %d\n", err);
    slhvkContextFree(ctx);
    return err;
  }

  uint8_t slhDsaSignature[SLHVK_SIGNATURE_SIZE];
  Time start, end;
  get_time(&start);

  for (int i = 0; i < testCasesCount; i++) {
    err = slhvkSignPure(
      ctx,
      testCases[i].skSeed,
      testCases[i].skPrf,
      testCases[i].pkSeed,
      testCases[i].pkRoot,
      NULL, // addrnd is empty for the ACVP test vectors
      testCases[i].contextString,
      testCases[i].contextStringSize,
      testCases[i].message,
      testCases[i].messageSize,
      slhDsaSignature
    );
    if (err) {
      eprintf("failed to run signing: %d\n", err);
      goto cleanup;
    }

    if (memcmp(slhDsaSignature, testCases[i].signature, SLHVK_SIGNATURE_SIZE) != 0) {
      eprintf("incorrect signature output for test case ID %d\n", testCases[i].id);
      err = -1;
      goto cleanup;
    }
  }
  get_time(&end);

  printf("computed %d valid signatures in %.2f ms\n", testCasesCount, time_delta_ms(start, end));

cleanup:
  slhvkContextFree(ctx);
  for (int i = 0; i < testCasesCount; i++) {
    freeSigningTestCase(&testCases[i]);
  }
  free(testCases);
  return err;
}
