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
  uint8_t skPrf[SLHVK_N] = {0};
  uint8_t skSeed[SLHVK_N] = {0x00, 0x00, 0x11, 0x22, 0xff, 0x29, 0x99, 0x90,
                             0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd};
  uint8_t pkRoot[SLHVK_N] = {0x8f, 0x0c, 0x8e, 0xe4, 0xaf, 0xdf, 0xc4, 0x64,
                             0x61, 0x75, 0xc8, 0x35, 0x1e, 0x17, 0x6a, 0x2f};

  uint8_t message[] = "hello world";
  uint8_t contextString[] = "string";
  uint8_t addrnd[] = {5, 4, 3, 2, 1, 0, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

  uint8_t slhDsaSignature[SLHVK_SIGNATURE_SIZE];

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
    NULL,
    slhDsaSignature
  );
  if (err) {
    eprintf("failed to run signing: %d\n", err);
    goto cleanup;
  }

  #define SIGS_LEN 2048
  uint8_t* pkSeeds[SIGS_LEN];
  uint8_t* pkRoots[SIGS_LEN];
  uint8_t* signatures[SIGS_LEN];
  uint8_t* messages[SIGS_LEN];
  size_t messageSizes[SIGS_LEN];
  uint8_t* contextStrings[SIGS_LEN];
  uint8_t contextStringSizes[SIGS_LEN];
  for (int i = 0; i < SIGS_LEN; i++) {
    pkSeeds[i] = pkSeed;
    pkRoots[i] = pkRoot;
    signatures[i] = slhDsaSignature;
    contextStrings[i] = contextString;
    contextStringSizes[i] = sizeof(contextString) - 1;
    messages[i] = message;
    messageSizes[i] = sizeof(message) - 1;
  }

  int verifyResults[SIGS_LEN];

  Time start, end;
  int nRuns = 0;
  getTime(&start);
  do {
    err = slhvkVerifyPure(
      ctx,
      SIGS_LEN, // sigs len
      contextStrings,
      contextStringSizes,
      pkSeeds,
      pkRoots,
      signatures,
      messages,
      messageSizes,
      verifyResults
    );
    if (err) {
      eprintf("failed to verify signature: %d\n", err);
      goto cleanup;
    }
    nRuns += SIGS_LEN;
    getTime(&end);
  } while (timeDeltaMillis(start, end) < 5000.0);

  printf("took %lu ns per sig verification\n", timeDeltaNanos(start, end) / nRuns);


cleanup:
  slhvkContextFree(ctx);
  return err;
}
