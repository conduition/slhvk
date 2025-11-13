#pragma once

#include <vulkan/vulkan.h>

// Security parameter.
#define SLHVK_N 16
#define SLHVK_HASH_WORDS (SLHVK_N / 4)

// Hypertree height
#define SLHVK_HYPERTREE_HEIGHT 63
#define SLHVK_HYPERTREE_LAYERS 7

// Winternitz parameter
#define SLHVK_LOG_W 4

// FORS parameters.
#define SLHVK_FORS_TREE_COUNT 14
#define SLHVK_FORS_TREE_HEIGHT 12

/*** The rest are derivative constants ***/

#define SLHVK_WOTS_CHAIN_LEN (1 << SLHVK_LOG_W)
#define SLHVK_WOTS_CHAIN_COUNT1 (8 * SLHVK_N / SLHVK_LOG_W)

// ceil(ceil(log2(SLHVK_WOTS_CHAIN_COUNT1 * (SLHVK_WOTS_CHAIN_LEN - 1))) / SLHVK_LOG_W)
#if SLHVK_LOG_W == 4
  #define SLHVK_WOTS_CHAIN_COUNT2 3
#elif SLHVK_LOG_W == 8
  #define SLHVK_WOTS_CHAIN_COUNT2 2
#endif

#define SLHVK_WOTS_CHAIN_COUNT (SLHVK_WOTS_CHAIN_COUNT1 + SLHVK_WOTS_CHAIN_COUNT2)
#define SLHVK_WOTS_SIGNATURE_SIZE (SLHVK_WOTS_CHAIN_COUNT * SLHVK_N)

#define SLHVK_FORS_DIGEST_SIZE ((SLHVK_FORS_TREE_COUNT * SLHVK_FORS_TREE_HEIGHT + 7) / 8)
#define SLHVK_FORS_LEAVES_COUNT (1 << SLHVK_FORS_TREE_HEIGHT)
#define SLHVK_FORS_SIGNATURE_SIZE (SLHVK_N * SLHVK_FORS_TREE_COUNT * (1 + SLHVK_FORS_TREE_HEIGHT))

#define SLHVK_HYPERTREE_SIGNATURE_SIZE (SLHVK_N * SLHVK_HYPERTREE_LAYERS * (SLHVK_XMSS_HEIGHT + SLHVK_WOTS_CHAIN_COUNT))

// XMSS parameters
#define SLHVK_XMSS_HEIGHT (SLHVK_HYPERTREE_HEIGHT / SLHVK_HYPERTREE_LAYERS)
#define SLHVK_XMSS_LEAVES (1 << SLHVK_XMSS_HEIGHT)
#define SLHVK_XMSS_CACHED_TREE_SIZE (SLHVK_N * SLHVK_XMSS_LEAVES)

// The size of a serialized single SLH-DSA signature.
#define SLHVK_SIGNATURE_SIZE (SLHVK_N + SLHVK_FORS_SIGNATURE_SIZE + SLHVK_HYPERTREE_SIGNATURE_SIZE)

// Number of msg digest bytes used to select an XMSS tree. (AKA 'M1').
#define SLHVK_TREE_ADDRESS_DIGEST_SIZE ((SLHVK_HYPERTREE_HEIGHT - SLHVK_XMSS_HEIGHT + 7) / 8)

// Number of msg digest bytes used to select the WOTS/FORS leaf key. (AKA 'M2')
#define SLHVK_KEYPAIR_ADDRESS_DIGEST_SIZE ((SLHVK_XMSS_HEIGHT + 7) / 8)

// Size of hashed message digest in bytes.
#define SLHVK_MESSAGE_DIGEST_SIZE (SLHVK_TREE_ADDRESS_DIGEST_SIZE + SLHVK_KEYPAIR_ADDRESS_DIGEST_SIZE + SLHVK_FORS_DIGEST_SIZE)


// Vulkan parameters
#define SLHVK_DEFAULT_WORK_GROUP_SIZE 64

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
