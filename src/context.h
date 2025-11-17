#include <stdint.h>
#include <vulkan/vulkan.h>

#define N SLHVK_N

#define KEYGEN_PIPELINE_DESCRIPTOR_COUNT 4
#define VERIFY_PIPELINE_DESCRIPTOR_COUNT 2

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
