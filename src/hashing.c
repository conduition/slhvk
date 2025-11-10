#include <stdint.h>
#include <string.h>

#include "sha256.h"
#include "params.h"

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
  sha256_clone(&shaCtx, shaCtxInitial);

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

  sha256_update(&shaCtx, adrsCompressed, 22);
  sha256_update(&shaCtx, forsRoots, SLHVK_N * SLHVK_FORS_TREE_COUNT);

  uint8_t forsPubkey[SLHVK_N];
  sha256_finalize(&shaCtx, forsPubkey, SLHVK_N);
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
  sha256_init(&hmacHashState);
  sha256_update(&hmacHashState, innerK, sizeof(innerK));
  sha256_update(&hmacHashState, optRand, SLHVK_N);
  if (contextStringSize > 0) {
    uint8_t contextStringHeader[2] = { 0, contextStringSize };
    sha256_update(&hmacHashState, contextStringHeader, sizeof(contextStringHeader));
    sha256_update(&hmacHashState, contextString, contextStringSize);
  }
  sha256_update(&hmacHashState, rawMessage, rawMessageSize);

  uint8_t hmacInnerHash[32];
  sha256_finalize(&hmacHashState, hmacInnerHash, sizeof(hmacInnerHash));

  sha256_init(&hmacHashState);
  sha256_update(&hmacHashState, outerK, sizeof(outerK));
  sha256_update(&hmacHashState, hmacInnerHash, sizeof(hmacInnerHash));
  sha256_finalize(&hmacHashState, randomizer, SLHVK_N);
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
  sha256_init(&shaCtx);
  sha256_update(&shaCtx, randomizer, SLHVK_N);
  sha256_update(&shaCtx, pkSeed, SLHVK_N);

  ShaContext shaCtxInner;
  sha256_clone(&shaCtxInner, &shaCtx);
  sha256_update(&shaCtxInner, pkRoot, SLHVK_N);
  if (contextStringSize > 0) {
    uint8_t contextStringHeader[2] = { 0, contextStringSize };
    sha256_update(&shaCtxInner, contextStringHeader, sizeof(contextStringHeader));
    sha256_update(&shaCtxInner, contextString, contextStringSize);
  }
  sha256_update(&shaCtxInner, rawMessage, rawMessageSize);
  uint8_t digestInner[32];
  sha256_finalize(&shaCtxInner, digestInner, sizeof(digestInner));

  sha256_update(&shaCtx, digestInner, sizeof(digestInner));

  uint8_t fullMessageDigest[SLHVK_MESSAGE_DIGEST_SIZE];
  uint8_t mgfCounter[4] = {0, 0, 0, 0};

  #if SLHVK_MESSAGE_DIGEST_SIZE <= 32
    sha256_update(&shaCtx, mgfCounter, 4);
    sha256_finalize(&shaCtx, fullMessageDigest, SLHVK_MESSAGE_DIGEST_SIZE);
  #elif SLHVK_MESSAGE_DIGEST_SIZE <= 64
    sha256_clone(&shaCtxInner, &shaCtx);
    sha256_update(&shaCtxInner, mgfCounter, 4);
    sha256_finalize(&shaCtxInner, fullMessageDigest, SLHVK_MESSAGE_DIGEST_SIZE);

    mgfCounter[3] += 1;
    sha256_update(&shaCtx, mgfCounter, 4);
    sha256_finalize(&shaCtx, &fullMessageDigest[32], SLHVK_MESSAGE_DIGEST_SIZE - 32);
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
