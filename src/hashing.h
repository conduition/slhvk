#pragma once
#include <stdint.h>

#include "sha256.h"
#include "slhvk.h"

void slhvkHashForsRootsToWotsMessage(
  const uint8_t* forsRoots,
  uint64_t treeAddress,
  uint32_t keypairAddress,
  const ShaContext* shaCtxInitial,
  uint32_t wotsMessage[SLHVK_WOTS_CHAIN_COUNT]
);

void slhvkMessagePrf(
  const uint8_t* skPrf,
  const uint8_t* optRand,
  const uint8_t* contextString,
  uint8_t contextStringSize,
  const uint8_t* rawMessage,
  size_t rawMessageSize,
  uint8_t randomizer[SLHVK_N]
);

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
);
