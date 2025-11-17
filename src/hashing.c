#include <stdint.h>
#include <string.h>

#include "sha256.h"
#include "slhvk.h"

const uint64_t TREE_ADDRESS_MASK = ((uint64_t) 1 << (SLHVK_HYPERTREE_HEIGHT - SLHVK_XMSS_HEIGHT)) - 1;
const uint32_t SIGNING_KEYPAIR_ADDRESS_MASK = (1 << SLHVK_XMSS_HEIGHT) - 1;


#define ADRS_TYPE_FORS_ROOTS 4

static void hashToBaseW(const uint8_t hash[SLHVK_N], uint32_t wotsMessage[SLHVK_WOTS_CHAIN_COUNT]) {
  #if SLHVK_WOTS_CHAIN_LEN == 256
    for (int i = 0; i < SLHVK_N; i++) {
      wotsMessage[i] = (uint32_t) hash[i];
    }
  #elif SLHVK_WOTS_CHAIN_LEN == 16
    for (int i = 0; i < SLHVK_N; i++) {
      wotsMessage[i * 2] = (uint32_t) (hash[i] >> 4) & 0xF;
      wotsMessage[i * 2 + 1] = (uint32_t) hash[i] & 0xF;
    }
  #else
    #error "Unexpected SLH-DSA W parameter, should be 256 or 16"
  #endif

  // wotsMessage is now initialized up to SLHVK_WOTS_CHAIN_COUNT1.
  // time to append the checksum.
  uint32_t checksum = 0;
  for (int i = 0; i < SLHVK_WOTS_CHAIN_COUNT1; i++) {
    checksum += SLHVK_WOTS_CHAIN_LEN - 1 - wotsMessage[i];
  }
  for (int i = 0; i < SLHVK_WOTS_CHAIN_COUNT2; i++) {
    wotsMessage[SLHVK_WOTS_CHAIN_COUNT - 1 - i] = checksum & (SLHVK_WOTS_CHAIN_LEN - 1);
    checksum >>= SLHVK_LOG_W;
  }
}

void slhvkHashForsRootsToWotsMessage(
  const uint8_t* forsRoots,
  uint64_t treeAddress,
  uint32_t keypairAddress,
  const ShaContext* shaCtxInitial,
  uint32_t wotsMessage[SLHVK_WOTS_CHAIN_COUNT]
) {
  ShaContext shaCtx;
  slhvkSha256Clone(&shaCtx, shaCtxInitial);

  uint8_t adrsCompressed[22] = {0};

  // Write the treeAddress
  for (size_t i = 0; i < 8; i++) {
    adrsCompressed[8 - i] = (uint8_t) treeAddress;
    treeAddress >>= 8;
  }

  adrsCompressed[9] = ADRS_TYPE_FORS_ROOTS;

  // Write the keypairAddress
  for (size_t i = 0; i < 4; i++) {
    adrsCompressed[13 - i] = (uint8_t) keypairAddress;
    keypairAddress >>= 8;
  }

  slhvkSha256Update(&shaCtx, adrsCompressed, 22);
  slhvkSha256Update(&shaCtx, forsRoots, SLHVK_N * SLHVK_FORS_TREE_COUNT);

  uint8_t forsPubkey[SLHVK_N];
  slhvkSha256Finalize(&shaCtx, forsPubkey, SLHVK_N);
  hashToBaseW(forsPubkey, wotsMessage);
}

void slhvkMessagePrf(
  const uint8_t* skPrf,
  const uint8_t* optRand,
  const uint8_t* contextString,
  uint8_t contextStringSize,
  const uint8_t* rawMessage,
  size_t rawMessageSize,
  uint8_t randomizer[SLHVK_N]
) {
  uint8_t keyBlock[64] = {0};
  memcpy(keyBlock, skPrf, SLHVK_N);

  uint8_t innerK[64] = {0};
  uint8_t outerK[64] = {0};

  for (int i = 0; i < 64; i++) {
    outerK[i] = keyBlock[i] ^ 0x5C;
    innerK[i] = keyBlock[i] ^ 0x36;
  }

  ShaContext hmacHashState;
  slhvkSha256Init(&hmacHashState);
  slhvkSha256Update(&hmacHashState, innerK, sizeof(innerK));
  slhvkSha256Update(&hmacHashState, optRand, SLHVK_N);
  if (contextString != NULL) {
    uint8_t contextStringHeader[2] = { 0, contextStringSize };
    slhvkSha256Update(&hmacHashState, contextStringHeader, sizeof(contextStringHeader));
    slhvkSha256Update(&hmacHashState, contextString, contextStringSize);
  }
  slhvkSha256Update(&hmacHashState, rawMessage, rawMessageSize);

  uint8_t hmacInnerHash[32];
  slhvkSha256Finalize(&hmacHashState, hmacInnerHash, sizeof(hmacInnerHash));

  slhvkSha256Init(&hmacHashState);
  slhvkSha256Update(&hmacHashState, outerK, sizeof(outerK));
  slhvkSha256Update(&hmacHashState, hmacInnerHash, sizeof(hmacInnerHash));
  slhvkSha256Finalize(&hmacHashState, randomizer, SLHVK_N);
}

void slhvkDigestAndSplitMsg(
  const uint8_t randomizer[SLHVK_N],
  const uint8_t pkSeed[SLHVK_N],
  const uint8_t pkRoot[SLHVK_N],
  const uint8_t* contextString,
  uint8_t contextStringSize,
  const uint8_t* rawMessage,
  size_t rawMessageSize,
  uint32_t forsIndices[SLHVK_FORS_TREE_COUNT],
  uint64_t* treeAddressPtr,
  uint32_t* signingKeypairAddressPtr
) {
  ShaContext shaCtx;
  slhvkSha256Init(&shaCtx);
  slhvkSha256Update(&shaCtx, randomizer, SLHVK_N);
  slhvkSha256Update(&shaCtx, pkSeed, SLHVK_N);

  ShaContext shaCtxInner;
  slhvkSha256Clone(&shaCtxInner, &shaCtx);
  slhvkSha256Update(&shaCtxInner, pkRoot, SLHVK_N);
  if (contextString != NULL) {
    uint8_t contextStringHeader[2] = { 0, contextStringSize };
    slhvkSha256Update(&shaCtxInner, contextStringHeader, sizeof(contextStringHeader));
    slhvkSha256Update(&shaCtxInner, contextString, contextStringSize);
  }
  slhvkSha256Update(&shaCtxInner, rawMessage, rawMessageSize);
  uint8_t digestInner[32];
  slhvkSha256Finalize(&shaCtxInner, digestInner, sizeof(digestInner));

  slhvkSha256Update(&shaCtx, digestInner, sizeof(digestInner));

  uint8_t fullMessageDigest[SLHVK_MESSAGE_DIGEST_SIZE];
  uint8_t mgfCounter[4] = {0, 0, 0, 0};

  #if SLHVK_MESSAGE_DIGEST_SIZE <= 32
    slhvkSha256Update(&shaCtx, mgfCounter, 4);
    slhvkSha256Finalize(&shaCtx, fullMessageDigest, SLHVK_MESSAGE_DIGEST_SIZE);
  #elif SLHVK_MESSAGE_DIGEST_SIZE <= 64
    slhvkSha256Clone(&shaCtxInner, &shaCtx);
    slhvkSha256Update(&shaCtxInner, mgfCounter, 4);
    slhvkSha256Finalize(&shaCtxInner, fullMessageDigest, SLHVK_MESSAGE_DIGEST_SIZE);

    mgfCounter[3] += 1;
    slhvkSha256Update(&shaCtx, mgfCounter, 4);
    slhvkSha256Finalize(&shaCtx, &fullMessageDigest[32], SLHVK_MESSAGE_DIGEST_SIZE - 32);
  #else
    #error "Unexpected message hash length, should be SLHVK_MESSAGE_DIGEST_SIZE <= 64"
  #endif

  uint8_t forsDigest[SLHVK_FORS_DIGEST_SIZE];
  uint64_t treeAddress = 0;
  uint32_t signingKeypairAddress = 0;

  size_t digestBytesRead = 0;
  for (int i = 0; i < SLHVK_FORS_DIGEST_SIZE; i++) {
    forsDigest[i] = fullMessageDigest[digestBytesRead++];
  }
  for (int i = 0; i < SLHVK_TREE_ADDRESS_DIGEST_SIZE; i++) {
    treeAddress = (treeAddress << 8) | fullMessageDigest[digestBytesRead++];
  }
  for (int i = 0; i < SLHVK_KEYPAIR_ADDRESS_DIGEST_SIZE; i++) {
    signingKeypairAddress = (signingKeypairAddress << 8) | fullMessageDigest[digestBytesRead++];
  }

  memset(forsIndices, 0, SLHVK_FORS_TREE_COUNT * sizeof(uint32_t));
  uint32_t bitsProcessed = 0;
  for (uint32_t i = 0; i < SLHVK_FORS_TREE_COUNT; i++) {
    for (uint32_t j = 0; j < SLHVK_FORS_TREE_HEIGHT; j++) {
      uint32_t byteIndex = bitsProcessed / 8;
      uint32_t bitIndexInByte = bitsProcessed % 8;
      uint32_t t = 1 & (forsDigest[byteIndex] >> (7 - bitIndexInByte));

      uint32_t bitIndexInBaseAWord = bitsProcessed % SLHVK_FORS_TREE_HEIGHT;
      forsIndices[i] |= t << (SLHVK_FORS_TREE_HEIGHT - 1 - bitIndexInBaseAWord);
      bitsProcessed += 1;
    }
  }

  *treeAddressPtr = treeAddress & TREE_ADDRESS_MASK;
  *signingKeypairAddressPtr = signingKeypairAddress & SIGNING_KEYPAIR_ADDRESS_MASK;
}
