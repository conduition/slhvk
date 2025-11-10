#include <stdint.h>

#include "sha256.h"
#include "params.h"

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
