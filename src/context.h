#pragma once
#include <stdint.h>
#include <vulkan/vulkan.h>

#include "slhvk.h"

#define N SLHVK_N

#define WOTS_TIPS_PRECOMPUTE_PIPELINE_DESCRIPTOR_COUNT 2
#define XMSS_LEAVES_PRECOMPUTE_PIPELINE_DESCRIPTOR_COUNT 3
#define XMSS_MERKLE_SIGN_PIPELINE_DESCRIPTOR_COUNT 4
#define WOTS_SIGN_PIPELINE_DESCRIPTOR_COUNT 3
#define FORS_LEAVES_GEN_PIPELINE_DESCRIPTOR_COUNT 4
#define FORS_MERKLE_SIGN_PIPELINE_DESCRIPTOR_COUNT 4

#define KEYGEN_PIPELINE_DESCRIPTOR_COUNT 4
#define VERIFY_PIPELINE_DESCRIPTOR_COUNT 2

// Buffer sizes
#define WOTS_CHAIN_BUFFER_SIZE (N * SLHVK_WOTS_CHAIN_COUNT * SLHVK_XMSS_LEAVES * SLHVK_HYPERTREE_LAYERS)
#define XMSS_NODES_BUFFER_SIZE (N * SLHVK_XMSS_LEAVES * SLHVK_HYPERTREE_LAYERS)
#define XMSS_MESSAGES_BUFFER_SIZE (sizeof(uint32_t) * SLHVK_WOTS_CHAIN_COUNT * SLHVK_HYPERTREE_LAYERS)
#define FORS_MESSAGE_BUFFER_SIZE (sizeof(uint32_t) * SLHVK_FORS_TREE_COUNT)
#define FORS_NODES_BUFFER_SIZE (N * SLHVK_FORS_TREE_COUNT * SLHVK_FORS_LEAVES_COUNT)
#define FORS_ROOTS_BUFFER_SIZE (N * SLHVK_FORS_TREE_COUNT)
#define FORS_PUBKEY_STAGING_BUFFER_SIZE (sizeof(uint32_t) * SLHVK_WOTS_CHAIN_COUNT)

typedef struct CommonSigningInputs {
  // The SHA256 state after absorbing the `pk_seed` and padding.
  uint32_t sha256State[8];

  // Secret seed from the private key.
  uint32_t skSeed[SLHVK_HASH_WORDS];

  // adrs[1:4]
  uint64_t treeAddress;

  // the index of the layer 0 keypair to be used for signing the message.
  uint32_t signingKeypairAddress;
} CommonSigningInputs;

typedef struct SlhvkContext_T {
  VkInstance instance;

  // Resources for the primary device
  VkPhysicalDevice           primaryPhysicalDevice;
  VkPhysicalDeviceProperties primaryDeviceProperties;
  uint32_t                   primaryDeviceQueueFamily;
  VkDevice                   primaryDevice;
  VkDescriptorPool           primaryDescriptorPool;
  VkCommandPool              primaryCommandPool;

  // WOTS chain precompute pipeline resources
  VkShaderModule        wotsTipsPrecomputeShader;
  VkPipeline            wotsTipsPrecomputePipeline;
  VkPipelineLayout      wotsTipsPrecomputePipelineLayout;
  VkDescriptorSet       wotsTipsPrecomputeDescriptorSet;
  VkDescriptorSetLayout wotsTipsPrecomputeDescriptorSetLayout;

  // XMSS leaf precompute pipeline resources
  VkShaderModule        xmssLeavesPrecomputeShader;
  VkPipeline            xmssLeavesPrecomputePipeline;
  VkPipelineLayout      xmssLeavesPrecomputePipelineLayout;
  VkDescriptorSet       xmssLeavesPrecomputeDescriptorSet;
  VkDescriptorSetLayout xmssLeavesPrecomputeDescriptorSetLayout;

  // XMSS merkle signing pipeline resources
  VkShaderModule        xmssMerkleSignShader;
  VkPipeline            xmssMerkleSignPipeline;
  VkPipelineLayout      xmssMerkleSignPipelineLayout;
  VkDescriptorSet       xmssMerkleSignDescriptorSet;
  VkDescriptorSetLayout xmssMerkleSignDescriptorSetLayout;

  // WOTS signing pipeline resources
  VkShaderModule        wotsSignShader;
  VkPipeline            wotsSignPipeline;
  VkPipelineLayout      wotsSignPipelineLayout;
  VkDescriptorSet       wotsSignDescriptorSet;
  VkDescriptorSetLayout wotsSignDescriptorSetLayout;

  /*******   Keygen resources  ***********/
  VkShaderModule        keygenWotsTipsShader;
  VkShaderModule        keygenXmssLeavesShader;
  VkShaderModule        keygenXmssRootsShader;
  VkPipeline            keygenWotsTipsPipeline;
  VkPipeline            keygenXmssLeavesPipeline;
  VkPipeline            keygenXmssRootsPipeline;
  VkPipelineLayout      keygenPipelineLayout;
  VkDescriptorSetLayout keygenDescriptorSetLayout;
  VkDescriptorSet       keygenDescriptorSet;

  /********  Verify resources  **********/
  VkShaderModule        verifyShader;
  VkPipeline            verifyPipeline;
  VkPipelineLayout      verifyPipelineLayout;
  VkDescriptorSetLayout verifyDescriptorSetLayout;
  VkDescriptorSet       verifyDescriptorSet;

  // primary device buffers
  VkBuffer primaryInputsBufferDeviceLocal;
  VkBuffer primaryInputsBufferHostVisible;
  VkBuffer primaryWotsChainBuffer;
  VkBuffer primaryXmssNodesBuffer;
  VkBuffer primaryXmssMessagesBuffer;
  VkBuffer primaryForsPubkeyStagingBuffer;
  VkBuffer primaryHypertreeSignatureBufferDeviceLocal;
  VkBuffer primaryHypertreeSignatureBufferHostVisible;

  // primary device memory backings (one per buffer)
  VkDeviceMemory primaryInputsBufferDeviceLocalMemory;
  VkDeviceMemory primaryInputsBufferHostVisibleMemory;
  VkDeviceMemory primaryWotsChainBufferMemory;
  VkDeviceMemory primaryXmssNodesBufferMemory;
  VkDeviceMemory primaryXmssMessagesBufferMemory;
  VkDeviceMemory primaryForsPubkeyStagingBufferMemory;
  VkDeviceMemory primaryHypertreeSignatureBufferDeviceLocalMemory;
  VkDeviceMemory primaryHypertreeSignatureBufferHostVisibleMemory;

  // primary device memory metadata
  VkMemoryPropertyFlags primaryDeviceLocalMemoryFlags;
  VkMemoryPropertyFlags primaryDeviceHostVisibleMemoryFlags;

  // primary device command buffers
  VkCommandBuffer primaryHypertreePresignCommandBuffer;
  VkCommandBuffer primaryHypertreeFinishCommandBuffer;

  // Resources for the secondary device
  VkPhysicalDevice           secondaryPhysicalDevice;
  VkPhysicalDeviceProperties secondaryDeviceProperties;
  uint32_t                   secondaryDeviceQueueFamily;
  VkDevice                   secondaryDevice;
  VkDescriptorPool           secondaryDescriptorPool;
  VkCommandPool              secondaryCommandPool;

  // FORS leaves gen pipeline resources
  VkShaderModule        forsLeavesGenShader;
  VkPipeline            forsLeavesGenPipeline;
  VkPipelineLayout      forsLeavesGenPipelineLayout;
  VkDescriptorSet       forsLeavesGenDescriptorSet;
  VkDescriptorSetLayout forsLeavesGenDescriptorSetLayout;

  // FORS merkle sign pipeline resources
  VkShaderModule        forsMerkleSignShader;
  VkPipeline            forsMerkleSignPipeline;
  VkPipelineLayout      forsMerkleSignPipelineLayout;
  VkDescriptorSet       forsMerkleSignDescriptorSet;
  VkDescriptorSetLayout forsMerkleSignDescriptorSetLayout;

  // secondary device buffers
  VkBuffer secondaryInputsBufferDeviceLocal;
  VkBuffer secondaryInputsBufferHostVisible;
  VkBuffer secondaryForsMessageBufferDeviceLocal;
  VkBuffer secondaryForsMessageBufferHostVisible;
  VkBuffer secondaryForsNodesBuffer;
  VkBuffer secondaryForsSignatureBufferDeviceLocal;
  VkBuffer secondaryForsSignatureBufferHostVisible;
  VkBuffer secondaryForsRootsBuffer;

  // secondary device memory backings (one per buffer)
  VkDeviceMemory secondaryInputsBufferDeviceLocalMemory;
  VkDeviceMemory secondaryInputsBufferHostVisibleMemory;
  VkDeviceMemory secondaryForsMessageBufferDeviceLocalMemory;
  VkDeviceMemory secondaryForsMessageBufferHostVisibleMemory;
  VkDeviceMemory secondaryForsNodesBufferMemory;
  VkDeviceMemory secondaryForsSignatureBufferDeviceLocalMemory;
  VkDeviceMemory secondaryForsSignatureBufferHostVisibleMemory;
  VkDeviceMemory secondaryForsRootsBufferMemory;

  // secondary device memory metadata
  VkMemoryPropertyFlags secondaryDeviceLocalMemoryFlags;
  VkMemoryPropertyFlags secondaryDeviceHostVisibleMemoryFlags;

  // secondary device command buffer
  VkCommandBuffer secondaryForsCommandBuffer;
} SlhvkContext_T;
