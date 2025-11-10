#pragma once
#include <stdint.h>

#include "sha256.h"

void slhvkHashForsRootsToWotsMessage(
  const uint8_t* forsRoots,
  uint64_t treeAddress,
  uint32_t keypairAddress,
  const ShaContext* shaCtxInitial,
  uint32_t wotsMessage[WOTS_CHAIN_COUNT]
);
