#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "../../utils.h"
#include "../../acvp.h"
#include "slhvk.h"

int main() {
  initTest();

  SlhvkContext ctx;
  int err = slhvkContextInit(&ctx);
  if (err) {
    eprintf("failed to init context: %d\n", err);
    return err;
  }

  VerifyTestCase* testCases = NULL;
  int testCasesCount = 0;
  err = readVerifyTestVectors(&testCases, &testCasesCount);
  if (err) {
    eprintf("failed to read verify test vectors: %d\n", err);
    slhvkContextFree(ctx);
    return err;
  }

  Time start, end;
  getTime(&start);

  int* verifyResults          = malloc(testCasesCount * sizeof(int));
  uint8_t** pkSeeds           = malloc(testCasesCount * sizeof(uint8_t*));
  uint8_t** pkRoots           = malloc(testCasesCount * sizeof(uint8_t*));
  uint8_t** messages          = malloc(testCasesCount * sizeof(uint8_t*));
  size_t* messageSizes        = malloc(testCasesCount * sizeof(size_t));
  uint8_t** signatures        = malloc(testCasesCount * sizeof(uint8_t*));
  uint8_t** contextStrings    = malloc(testCasesCount * sizeof(uint8_t*));
  uint8_t* contextStringSizes = malloc(testCasesCount * sizeof(uint8_t));

  for (int i = 0; i < testCasesCount; i++) {
    pkSeeds[i] = testCases[i].pkSeed;
    pkRoots[i] = testCases[i].pkRoot;
    messages[i] = testCases[i].message;
    messageSizes[i] = testCases[i].messageSize;
    signatures[i] = testCases[i].signature;
    contextStrings[i] = testCases[i].contextString;
    contextStringSizes[i] = (uint8_t) testCases[i].contextStringSize;
  }
  err = slhvkVerifyPure(
    ctx,
    testCasesCount,
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
    eprintf("failed to verify signatures: %d\n", err);
    goto cleanup;
  }
  getTime(&end);

  for (int i = 0; i < testCasesCount; i++) {
    if ((verifyResults[i] == 0) != testCases[i].testPassed) {
      eprintf("signature failed to verify as expected");
      eprintf("test case ID: %d\n", testCases[i].id);
      err = -1;
      goto cleanup;
    }
  }

  printf("verified %d test cases in %.2f ms\n", testCasesCount, timeDeltaMillis(start, end));

cleanup:
  slhvkContextFree(ctx);
  for (int i = 0; i < testCasesCount; i++) {
    freeVerifyTestCase(&testCases[i]);
  }
  free(testCases);
  free(verifyResults);
  free(pkSeeds);
  free(pkRoots);
  free(messages);
  free(messageSizes);
  free(signatures);
  free(contextStrings);
  free(contextStringSizes);

  return err;
}
