#pragma once

// Security parameter.
#define N 16
#define HASH_WORDS (N / 4)

// Hypertree height
#define HYPERTREE_HEIGHT 63
#define HYPERTREE_LAYERS 7

// Winternitz parameter
#define LOG_W 4

// FORS parameters.
#define FORS_TREE_COUNT 14
#define FORS_TREE_HEIGHT 12

/*** The rest are derivative constants ***/

#define WOTS_CHAIN_LEN (1 << LOG_W)
#define WOTS_CHAIN_COUNT1 (8 * N / LOG_W)

// ceil(ceil(log2(WOTS_CHAIN_COUNT1 * (WOTS_CHAIN_LEN - 1))) / LOG_W)
#if LOG_W == 4
  #define WOTS_CHAIN_COUNT2 3
#elif LOG_W == 8
  #define WOTS_CHAIN_COUNT2 2
#endif

#define WOTS_CHAIN_COUNT (WOTS_CHAIN_COUNT1 + WOTS_CHAIN_COUNT2)
#define WOTS_SIGNATURE_SIZE (WOTS_CHAIN_COUNT * N)

#define FORS_DIGEST_SIZE ((FORS_TREE_COUNT * FORS_TREE_HEIGHT + 7) / 8)
#define FORS_LEAVES_COUNT (1 << FORS_TREE_HEIGHT)
#define FORS_SIGNATURE_SIZE (N * FORS_TREE_COUNT * (1 + FORS_TREE_HEIGHT))

#define HYPERTREE_SIGNATURE_OFFSET (N + FORS_SIGNATURE_SIZE)
#define HYPERTREE_SIGNATURE_SIZE (N * HYPERTREE_LAYERS * (XMSS_HEIGHT + WOTS_CHAIN_COUNT))

// XMSS parameters
#define XMSS_HEIGHT (HYPERTREE_HEIGHT / HYPERTREE_LAYERS)
#define XMSS_LEAVES (1 << XMSS_HEIGHT)
#define XMSS_CACHED_TREE_SIZE (N * XMSS_LEAVES)
#define XMSS_MERKLE_PATH_SIZE (XMSS_HEIGHT * N)
#define XMSS_SIGNATURE_SIZE (XMSS_MERKLE_PATH_SIZE + WOTS_SIGNATURE_SIZE)

// The size of a serialized single SLH-DSA signature.
#define SLH_DSA_SIGNATURE_SIZE (N + FORS_SIGNATURE_SIZE + HYPERTREE_SIGNATURE_SIZE)

// Number of msg digest bytes used to select an XMSS tree.
#define M1 ((HYPERTREE_HEIGHT - XMSS_HEIGHT + 7) / 8)

// Number of msg digest bytes used to select the WOTS/FORS leaf key.
#define M2 ((XMSS_HEIGHT + 7) / 8)

// Size of hashed message digest in bytes.
#define M (M1 + M2 + FORS_DIGEST_SIZE)


// Vulkan parameters
#define SLHVK_DEFAULT_WORK_GROUP_SIZE 64
