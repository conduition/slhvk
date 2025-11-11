#include <vulkan/vulkan.h>

#include "params.h"

typedef struct SlhvkContext_T* SlhvkContext;

typedef enum SlhvkError {
  SLHVK_SUCCESS = 0,
  SLHVK_ERROR_NO_COMPUTE_DEVICE = 40,
  SLHVK_ERROR_MEMORY_TYPE_NOT_FOUND = 41,
} SlhvkError;

void slhvkContextFree(SlhvkContext ctx);
int slhvkContextInit(SlhvkContext* ctxPtr);

int slhvkSignPure(
  SlhvkContext ctx,
  const uint8_t skSeed[SLHVK_N],
  const uint8_t skPrf[SLHVK_N],
  const uint8_t pkSeed[SLHVK_N],
  const uint8_t pkRoot[SLHVK_N],
  const uint8_t addrnd[SLHVK_N],
  const uint8_t* contextString,
  uint8_t contextStringSize,
  const uint8_t* rawMessage,
  size_t rawMessageSize,
  uint8_t signatureOutput[SLHVK_SIGNATURE_SIZE]
);

int slhvkKeygen(
  SlhvkContext ctx,
  uint32_t keysCount,
  const uint8_t* const* skSeeds,
  const uint8_t* const* pkSeeds,
  uint8_t** pkRootsOut
);
