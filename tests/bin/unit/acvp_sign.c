#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "../../utils.h"
#include "../../acvp.h"
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

  SigningTestCase* testCases = NULL;
  int testCasesCount = 0;
  err = readSigningTestVectors(&testCases, &testCasesCount);
  if (err) {
    eprintf("failed to read signing test vectors: %d\n", err);
    slhvkContextFree(ctx);
    return err;
  }

  uint8_t pkRoot[SLHVK_N];
  uint8_t cachedRootTree[SLHVK_XMSS_CACHED_TREE_SIZE];
  uint8_t slhDsaSignature[SLHVK_SIGNATURE_SIZE];
  Time start, end;
  getTime(&start);

  for (int r = 0; r < 2; r++) {
    for (int i = 0; i < testCasesCount; i++) {
      if (r > 0) {
        err = slhvkKeygen(
          ctx,
          testCases[i].skSeed,
          testCases[i].pkSeed,
          pkRoot,
          cachedRootTree
        );
        if (err) {
          eprintf("failed to run keygen: %d\n", err);
          goto cleanup;
        }

        if (memcmp(pkRoot, testCases[i].pkRoot, SLHVK_N) != 0) {
          eprintf("incorrect pkRoot output during keygen for test case ID %d\n", testCases[i].id);
          err = -1;
          goto cleanup;
        }
      }

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
        r > 0 ? cachedRootTree : NULL,
        slhDsaSignature
      );
      if (err) {
        eprintf("failed to run signing: %d\n", err);
        goto cleanup;
      }

      if (memcmp(slhDsaSignature, testCases[i].signature, SLHVK_SIGNATURE_SIZE) != 0) {
        eprintf(
          "incorrect signature output for test case ID %d (cached root tree: %s)\n",
          testCases[i].id,
          r > 0 ? "yes" : "no"
        );
        // for (int i = 0; i < SLHVK_SIGNATURE_SIZE; i++) {
        //   eprintf("%02x", slhDsaSignature[i]);
        // }
        // eprintf("\n");
        err = -1;
        goto cleanup;
      }
    }
  }
  getTime(&end);

  printf("computed %d valid signatures in %.2f ms\n", testCasesCount * 2, timeDeltaMillis(start, end));

cleanup:
  slhvkContextFree(ctx);
  for (int i = 0; i < testCasesCount; i++) {
    freeSigningTestCase(&testCases[i]);
  }
  free(testCases);
  return err;
}
