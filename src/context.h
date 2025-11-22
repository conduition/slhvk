#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <vulkan/vulkan.h>

#include "slhvk.h"

#define N SLHVK_N

#define PRIMARY_SIGNING_PIPELINE_DESCRIPTOR_COUNT 5
#define SECONDARY_SIGNING_PIPELINE_DESCRIPTOR_COUNT 4
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

  // Indicates if top-level XMSS tree leaves have been preloaded into memory, saving
  // us from redundant recomputation.
  uint32_t cachedTreeLayers;
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

  // Resources for the secondary device
  VkPhysicalDevice           secondaryPhysicalDevice;
  VkPhysicalDeviceProperties secondaryDeviceProperties;
  uint32_t                   secondaryDeviceQueueFamily;
  VkDevice                   secondaryDevice;
  VkDescriptorPool           secondaryDescriptorPool;
  VkCommandPool              secondaryCommandPool;


  /*******  Signing resources (primary)  **********/
  VkShaderModule        wotsTipsPrecomputeShader;
  VkShaderModule        xmssLeavesPrecomputeShader;
  VkShaderModule        xmssMerkleSignShader;
  VkShaderModule        wotsSignShader;
  VkPipeline            wotsTipsPrecomputePipeline;
  VkPipeline            xmssLeavesPrecomputePipeline;
  VkPipeline            xmssMerkleSignPipeline;
  VkPipeline            wotsSignPipeline;
  VkPipelineLayout      primarySigningPipelineLayout;
  VkDescriptorSetLayout primarySigningDescriptorSetLayout;
  VkDescriptorSet       primarySigningDescriptorSet;
  VkEvent               primaryXmssRootTreeCopyDoneEvent;

  /*******  Signing resources (secondary)  **********/
  VkShaderModule        forsLeavesGenShader;
  VkShaderModule        forsMerkleSignShader;
  VkPipeline            forsLeavesGenPipeline;
  VkPipeline            forsMerkleSignPipeline;
  VkPipelineLayout      secondarySigningPipelineLayout;
  VkDescriptorSetLayout secondarySigningDescriptorSetLayout;
  VkDescriptorSet       secondarySigningDescriptorSet;

  /*******  Keygen resources  ***********/
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

  // primary device memory metadata
  VkMemoryPropertyFlags primaryDeviceLocalMemoryFlags;
  VkMemoryPropertyFlags primaryDeviceHostVisibleMemoryFlags;

  // secondary device memory metadata
  VkMemoryPropertyFlags secondaryDeviceLocalMemoryFlags;
  VkMemoryPropertyFlags secondaryDeviceHostVisibleMemoryFlags;

  // primary device command buffers
  VkCommandBuffer primaryHypertreePresignCommandBuffer;
  VkCommandBuffer primaryHypertreeFinishCommandBuffer;
  VkCommandBuffer primaryXmssRootTreeCopyCommandBuffer;
  VkCommandBuffer primaryKeygenCommandBuffer;
  VkCommandBuffer primaryVerifyCommandBuffer;

  // secondary device command buffer
  VkCommandBuffer secondaryForsCommandBuffer;
} SlhvkContext_T;
