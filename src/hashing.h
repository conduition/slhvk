#include <stdint.h>

#include "params.h"

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
