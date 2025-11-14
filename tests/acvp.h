#include <string.h>
#include "vendor/cJSON.h"
#include "slhvk.h"

#define ERROR_FILE_READ 1
#define ERROR_INVALID_JSON 2
#define ERROR_CANNOT_FIND_PARAMETER_SET_TESTS 3
#define ERROR_INVALID_HEX_DATA 4

size_t getFileSize(FILE* fp) {
  int prev = ftell(fp);
  if (prev < 0) {
    perror("checking file pointer offset");
    return 0;
  }
  int err = fseek(fp, 0, SEEK_END);
  if (err) {
    perror("seeking to end of file");
    return 0;
  }
  int size = ftell(fp);
  if (size < 0) {
    perror("checking file pointer offset after seeking");
    return 0;
  }
  err = fseek(fp, prev, SEEK_SET);
  if (err) {
    perror("seeking back to initial file pointer offset");
    return 0;
  }
  return (size_t) size;
}

char* readTextFile(const char* fname) {
  FILE* fp = fopen(fname, "r");
  if (fp == NULL) {
    perror("reading test file");
    return NULL;
  }

  size_t size = getFileSize(fp);
  if (size == 0) {
    return NULL;
  }

  char* fileData = malloc(size);
  size_t bytesRead = fread(fileData, 1, size, fp);
  if (bytesRead < size) {
    perror("failed to read entire file");
    return NULL;
  }

  // This must be freed by the caller.
  return fileData;
}

int hexDecodeChar(char hexChar, uint8_t* out) {
  if (hexChar >= 'A' && hexChar <= 'F') {
    *out = hexChar - 'A' + 10;
  } else if (hexChar >= 'a' && hexChar <= 'a') {
    *out = hexChar - 'a' + 10;
  } else if (hexChar >= '0' && hexChar <= '9') {
    *out = hexChar - '0';
  } else {
    return ERROR_INVALID_HEX_DATA;
  }
  return 0;
}

int hexDecode(const char* hexString, uint8_t* output, size_t bytes) {
  if ((size_t) strlen(hexString) != 2 * bytes) {
    return ERROR_INVALID_HEX_DATA;
  }

  int err;
  uint8_t hi, lo;
  for (size_t i = 0; i < bytes; i++) {
    err = hexDecodeChar(hexString[i * 2], &hi);
    if (err) return err;
    err = hexDecodeChar(hexString[i * 2 + 1], &lo);
    if (err) return err;
    output[i] = (hi << 4) | lo;
  }
  return 0;
}

typedef struct KeygenTestCase {
  int id;
  uint8_t skSeed[SLHVK_N];
  uint8_t skPrf[SLHVK_N];
  uint8_t pkSeed[SLHVK_N];
  uint8_t pkRoot[SLHVK_N];
} KeygenTestCase;

int readKeygenTestVectors(KeygenTestCase** testCasesOutPtr, int* testCasesCountPtr) {
  char* keygenJsonRaw = readTextFile("../vectors/keygen.json");
  if (keygenJsonRaw == NULL) {
    return ERROR_FILE_READ;
  }

  cJSON* keygenJson = cJSON_Parse(keygenJsonRaw);
  free(keygenJsonRaw);
  if (keygenJson == NULL) {
    return ERROR_INVALID_JSON;
  }

  int err = 0;
  KeygenTestCase* testCases = NULL;

  cJSON* testGroupJson = NULL;
  cJSON* group;
  cJSON_ArrayForEach(group, keygenJson) {
    char* parameterSet = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(group, "parameterSet"));
    if (parameterSet == NULL) {
      err = ERROR_INVALID_JSON;
      goto cleanup;
    }
    if (strcmp(parameterSet, "SLH-DSA-SHA2-128s") == 0) {
      testGroupJson = group;
      break;
    }
  }
  if (testGroupJson == NULL) {
    err = ERROR_CANNOT_FIND_PARAMETER_SET_TESTS;
    goto cleanup;
  }


  cJSON* testCasesJson = cJSON_GetObjectItemCaseSensitive(testGroupJson, "tests");
  if (!cJSON_IsArray(testCasesJson)) {
    err = ERROR_INVALID_JSON;
    goto cleanup;
  }

  int testCasesCount = cJSON_GetArraySize(testCasesJson);
  testCases = malloc(sizeof(KeygenTestCase) * testCasesCount);

  cJSON* testCaseJson;
  int i = 0;
  cJSON_ArrayForEach(testCaseJson, testCasesJson) {
    char* skSeedHex = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(testCaseJson, "skSeed"));
    char* skPrfHex = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(testCaseJson, "skPrf"));
    char* pkSeedHex = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(testCaseJson, "pkSeed"));
    char* pubkeyHex = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(testCaseJson, "pk"));
    int testCaseID = (int) cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(testCaseJson, "tcId"));

    if (skSeedHex == NULL || skPrfHex == NULL || pkSeedHex == NULL || pubkeyHex == NULL) {
      err = ERROR_INVALID_JSON;
      goto cleanup;
    }

    testCases[i].id = testCaseID;

    // Extract the pkRoot from the test case pubkey
    uint8_t pubkey[SLHVK_N * 2];
    err = hexDecode(pubkeyHex, pubkey, sizeof(pubkey));
    if (err) goto cleanup;
    memcpy(testCases[i].pkRoot, &pubkey[SLHVK_N], SLHVK_N);

    // Copy the seed values
    err = hexDecode(skSeedHex, testCases[i].skSeed, SLHVK_N);
    if (err) goto cleanup;
    err = hexDecode(skPrfHex, testCases[i].skPrf, SLHVK_N);
    if (err) goto cleanup;
    err = hexDecode(pkSeedHex, testCases[i].pkSeed, SLHVK_N);
    if (err) goto cleanup;

    i += 1;
  }

  cJSON_Delete(keygenJson);
  *testCasesOutPtr = testCases;
  *testCasesCountPtr = testCasesCount;
  return 0;

cleanup:
  cJSON_Delete(keygenJson);
  free(testCases);
  return err;
}
