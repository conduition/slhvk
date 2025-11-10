#include <vulkan/vulkan.h>

#include "params.h"

typedef struct SlhvkContext {
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
} SlhvkContext;

typedef enum SlhvkError {
  SLHVK_SUCCESS = 0,
  SLHVK_ERROR_NO_COMPUTE_DEVICE = 40,
  SLHVK_ERROR_MEMORY_TYPE_NOT_FOUND = 41,
} SlhvkError;

void slhvkContextFree(SlhvkContext* ctx);
int slhvkContextInit(SlhvkContext* ctx);

int slhvkSignPure(
  SlhvkContext* ctx,
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
