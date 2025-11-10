#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <vulkan/vulkan.h>

#include "params.h"
#include "sha256.h"
#include "context.h"
#include "hashing.h"
#include "fors.h"
#include "shaders/wots_tips_precompute.h"
#include "shaders/xmss_leaves_precompute.h"
#include "shaders/xmss_merkle_sign.h"
#include "shaders/wots_sign.h"
#include "shaders/fors_leaves_gen.h"
#include "shaders/fors_merkle_sign.h"

#define MAX_DESCRIPTOR_SETS_PER_DEVICE 10
#define MAX_DESCRIPTORS_PER_DEVICE     20

#define WOTS_CHAIN_BUFFER_SIZE (N * WOTS_CHAIN_COUNT * XMSS_LEAVES * HYPERTREE_LAYERS)
#define XMSS_NODES_BUFFER_SIZE (N * XMSS_LEAVES * HYPERTREE_LAYERS)
#define XMSS_MESSAGES_BUFFER_SIZE (sizeof(uint32_t) * WOTS_CHAIN_COUNT * HYPERTREE_LAYERS)
#define FORS_MESSAGE_BUFFER_SIZE (sizeof(uint32_t) * FORS_TREE_COUNT)
#define FORS_NODES_BUFFER_SIZE (N * FORS_TREE_COUNT * FORS_LEAVES_COUNT)
#define FORS_ROOTS_BUFFER_SIZE (N * FORS_TREE_COUNT)
#define FORS_PUBKEY_STAGING_BUFFER_SIZE (sizeof(uint32_t) * WOTS_CHAIN_COUNT)

#define WOTS_TIPS_PRECOMPUTE_PIPELINE_DESCRIPTOR_COUNT 2
#define XMSS_LEAVES_PRECOMPUTE_PIPELINE_DESCRIPTOR_COUNT 3
#define XMSS_MERKLE_SIGN_PIPELINE_DESCRIPTOR_COUNT 4
#define WOTS_SIGN_PIPELINE_DESCRIPTOR_COUNT 3

#define FORS_LEAVES_GEN_PIPELINE_DESCRIPTOR_COUNT 4
#define FORS_MERKLE_SIGN_PIPELINE_DESCRIPTOR_COUNT 4

#define SPEC_CONSTANTS_COUNT 9

static uint32_t numWorkGroups(uint32_t threadsCount) {
  return (threadsCount + SLHVK_DEFAULT_WORK_GROUP_SIZE - 1) / SLHVK_DEFAULT_WORK_GROUP_SIZE;
}

static int findDeviceComputeQueueFamily(VkPhysicalDevice physicalDevice) {
  uint32_t queueFamilyCount = 0;
  vkGetPhysicalDeviceQueueFamilyProperties(physicalDevice, &queueFamilyCount, NULL);
  VkQueueFamilyProperties* queueFamilies = malloc(queueFamilyCount * sizeof(VkQueueFamilyProperties));
  vkGetPhysicalDeviceQueueFamilyProperties(physicalDevice, &queueFamilyCount, queueFamilies);
  for (uint32_t i = 0; i < queueFamilyCount; i++) {
    if (queueFamilies[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
      return i;
    }
  }
  free(queueFamilies);
  return -1;
}

static int allocateBufferMemory(
  VkDevice device,
  VkPhysicalDevice physicalDevice,
  VkBuffer buffer,
  VkMemoryPropertyFlags desiredMemoryFlags,
  VkMemoryPropertyFlags* actualMemoryFlags,
  VkDeviceMemory* memoryPtr
) {
  VkDeviceMemory memory = NULL;
  int err = 0;

  VkMemoryRequirements memRequirements;
  vkGetBufferMemoryRequirements(device, buffer, &memRequirements);
  uint32_t memoryTypeBits = memRequirements.memoryTypeBits;
  size_t   memorySize     = memRequirements.size;

  // The given buffer does not have any compatible memory types.
  if (memoryTypeBits == 0)
    return SLHVK_ERROR_MEMORY_TYPE_NOT_FOUND;

  VkPhysicalDeviceMemoryProperties memoryProperties;
  vkGetPhysicalDeviceMemoryProperties(physicalDevice, &memoryProperties);

  // Find an appropriate memory type.
  int memoryTypeIndex = -1;
  VkMemoryPropertyFlags memoryFlags;
  for (uint32_t i = 0; i < memoryProperties.memoryTypeCount; i++) {
    memoryFlags = memoryProperties.memoryTypes[i].propertyFlags;
    bool memoryCanSupportBuffer = !!(memoryTypeBits & (1 << i));
    bool memoryHasDesiredProperties = (memoryFlags & desiredMemoryFlags) == desiredMemoryFlags;

    if (memoryCanSupportBuffer && memoryHasDesiredProperties) {
      memoryTypeIndex = (int) i;
      break;
    }
  }

  if (memoryTypeIndex < 0)
    return SLHVK_ERROR_MEMORY_TYPE_NOT_FOUND;

  // Allocates memory on the device.
  VkMemoryAllocateInfo memoryAllocateInfo = {
    .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
    .allocationSize = memorySize,
    .memoryTypeIndex = (uint32_t) memoryTypeIndex,
  };
  err = vkAllocateMemory(device, &memoryAllocateInfo, NULL, &memory);
  if (err) return err;

  // Bind the vulkan buffer object to the memory backing.
  err = vkBindBufferMemory(device, buffer, memory, /* offset */ 0);
  if (err) {
    vkFreeMemory(device, memory, NULL);
    return err;
  }

  *memoryPtr = memory;
  if (actualMemoryFlags != NULL) {
    *actualMemoryFlags = memoryFlags;
  }
  return 0;
}

static int setupDescriptorSetLayout(
  VkDevice device,
  uint32_t bindingCount,
  VkDescriptorSetLayout* descriptorSetLayout
) {
  VkDescriptorSetLayoutBinding* bindings = malloc(bindingCount * sizeof(VkDescriptorSetLayoutBinding));

  for (uint32_t i = 0; i < bindingCount; i++) {
    VkDescriptorSetLayoutBinding binding = {
      .binding = i,
      .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
      .descriptorCount = 1,
      .stageFlags = VK_SHADER_STAGE_COMPUTE_BIT,
    };
    bindings[i] = binding;
  };

  VkDescriptorSetLayoutCreateInfo layoutCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
    .bindingCount = bindingCount,
    .pBindings = bindings,
  };

  int err = vkCreateDescriptorSetLayout(device, &layoutCreateInfo, NULL, descriptorSetLayout);
  free(bindings);
  return err;
}


// Bind an array of storage buffers to the descriptor set.
static void bindBuffersToDescriptorSet(
  VkDevice device,
  const VkBuffer* buffers,
  uint32_t buffersCount,
  VkDescriptorSet descriptorSet
) {
  VkMemoryRequirements memRequirements;
  for (uint32_t i = 0; i < buffersCount; i++) {
    vkGetBufferMemoryRequirements(device, buffers[i], &memRequirements);

    // Specify the buffer to bind to the descriptor.
    VkDescriptorBufferInfo bufferInfo = {
      .buffer = buffers[i],
      .offset = 0,
      .range = memRequirements.size,
    };

    VkWriteDescriptorSet writeDescriptorSet = {
      .sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
      .dstSet = descriptorSet, // write to this descriptor set.
      .dstBinding = i,
      .descriptorCount = 1, // update a single descriptor.
      .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
      .pBufferInfo = &bufferInfo,
    };

    vkUpdateDescriptorSets(
      device,
      1, &writeDescriptorSet,
      0, NULL
    );
  }
}


void slhvkContextFree(SlhvkContext* ctx) {
  if (ctx != NULL) {
    /********** Free device resources **********/

    // Primary device buffers
    vkDestroyBuffer(ctx->primaryDevice, ctx->primaryInputsBufferDeviceLocal, NULL);
    vkDestroyBuffer(ctx->primaryDevice, ctx->primaryInputsBufferHostVisible, NULL);
    vkDestroyBuffer(ctx->primaryDevice, ctx->primaryWotsChainBuffer, NULL);
    vkDestroyBuffer(ctx->primaryDevice, ctx->primaryXmssNodesBuffer, NULL);
    vkDestroyBuffer(ctx->primaryDevice, ctx->primaryXmssMessagesBuffer, NULL);
    vkDestroyBuffer(ctx->primaryDevice, ctx->primaryForsPubkeyStagingBuffer, NULL);
    vkDestroyBuffer(ctx->primaryDevice, ctx->primaryHypertreeSignatureBufferDeviceLocal, NULL);
    vkDestroyBuffer(ctx->primaryDevice, ctx->primaryHypertreeSignatureBufferHostVisible, NULL);

    // Secondary device buffers
    vkDestroyBuffer(ctx->secondaryDevice, ctx->secondaryInputsBufferDeviceLocal, NULL);
    vkDestroyBuffer(ctx->secondaryDevice, ctx->secondaryInputsBufferHostVisible, NULL);
    vkDestroyBuffer(ctx->secondaryDevice, ctx->secondaryForsMessageBufferDeviceLocal, NULL);
    vkDestroyBuffer(ctx->secondaryDevice, ctx->secondaryForsMessageBufferHostVisible, NULL);
    vkDestroyBuffer(ctx->secondaryDevice, ctx->secondaryForsNodesBuffer, NULL);
    vkDestroyBuffer(ctx->secondaryDevice, ctx->secondaryForsSignatureBufferDeviceLocal, NULL);
    vkDestroyBuffer(ctx->secondaryDevice, ctx->secondaryForsSignatureBufferHostVisible, NULL);
    vkDestroyBuffer(ctx->secondaryDevice, ctx->secondaryForsRootsBuffer, NULL);

    // Primary device memory
    vkFreeMemory(ctx->primaryDevice, ctx->primaryInputsBufferDeviceLocalMemory, NULL);
    vkFreeMemory(ctx->primaryDevice, ctx->primaryInputsBufferHostVisibleMemory, NULL);
    vkFreeMemory(ctx->primaryDevice, ctx->primaryWotsChainBufferMemory, NULL);
    vkFreeMemory(ctx->primaryDevice, ctx->primaryXmssNodesBufferMemory, NULL);
    vkFreeMemory(ctx->primaryDevice, ctx->primaryXmssMessagesBufferMemory, NULL);
    vkFreeMemory(ctx->primaryDevice, ctx->primaryForsPubkeyStagingBufferMemory, NULL);
    vkFreeMemory(ctx->primaryDevice, ctx->primaryHypertreeSignatureBufferDeviceLocalMemory, NULL);
    vkFreeMemory(ctx->primaryDevice, ctx->primaryHypertreeSignatureBufferHostVisibleMemory, NULL);

    // Secondary device memory
    vkFreeMemory(ctx->secondaryDevice, ctx->secondaryInputsBufferDeviceLocalMemory, NULL);
    vkFreeMemory(ctx->secondaryDevice, ctx->secondaryInputsBufferHostVisibleMemory, NULL);
    vkFreeMemory(ctx->secondaryDevice, ctx->secondaryForsMessageBufferDeviceLocalMemory, NULL);
    vkFreeMemory(ctx->secondaryDevice, ctx->secondaryForsMessageBufferHostVisibleMemory, NULL);
    vkFreeMemory(ctx->secondaryDevice, ctx->secondaryForsNodesBufferMemory, NULL);
    vkFreeMemory(ctx->secondaryDevice, ctx->secondaryForsSignatureBufferDeviceLocalMemory, NULL);
    vkFreeMemory(ctx->secondaryDevice, ctx->secondaryForsSignatureBufferHostVisibleMemory, NULL);
    vkFreeMemory(ctx->secondaryDevice, ctx->secondaryForsRootsBufferMemory, NULL);

    // WOTS tip precompute pipeline
    vkDestroyDescriptorSetLayout(ctx->primaryDevice, ctx->wotsTipsPrecomputeDescriptorSetLayout, NULL);
    vkDestroyPipeline(ctx->primaryDevice, ctx->wotsTipsPrecomputePipeline, NULL);
    vkDestroyPipelineLayout(ctx->primaryDevice, ctx->wotsTipsPrecomputePipelineLayout, NULL);
    vkDestroyShaderModule(ctx->primaryDevice, ctx->wotsTipsPrecomputeShader, NULL);

    // XMSS leaf precompute pipeline
    vkDestroyDescriptorSetLayout(ctx->primaryDevice, ctx->xmssLeavesPrecomputeDescriptorSetLayout, NULL);
    vkDestroyPipeline(ctx->primaryDevice, ctx->xmssLeavesPrecomputePipeline, NULL);
    vkDestroyPipelineLayout(ctx->primaryDevice, ctx->xmssLeavesPrecomputePipelineLayout, NULL);
    vkDestroyShaderModule(ctx->primaryDevice, ctx->xmssLeavesPrecomputeShader, NULL);

    // XMSS merkle sign pipeline
    vkDestroyDescriptorSetLayout(ctx->primaryDevice, ctx->xmssMerkleSignDescriptorSetLayout, NULL);
    vkDestroyPipeline(ctx->primaryDevice, ctx->xmssMerkleSignPipeline, NULL);
    vkDestroyPipelineLayout(ctx->primaryDevice, ctx->xmssMerkleSignPipelineLayout, NULL);
    vkDestroyShaderModule(ctx->primaryDevice, ctx->xmssMerkleSignShader, NULL);

    // WOTS sign pipeline
    vkDestroyDescriptorSetLayout(ctx->primaryDevice, ctx->wotsSignDescriptorSetLayout, NULL);
    vkDestroyPipeline(ctx->primaryDevice, ctx->wotsSignPipeline, NULL);
    vkDestroyPipelineLayout(ctx->primaryDevice, ctx->wotsSignPipelineLayout, NULL);
    vkDestroyShaderModule(ctx->primaryDevice, ctx->wotsSignShader, NULL);

    // FORS leaves gen pipeline
    vkDestroyDescriptorSetLayout(ctx->secondaryDevice, ctx->forsLeavesGenDescriptorSetLayout, NULL);
    vkDestroyPipeline(ctx->secondaryDevice, ctx->forsLeavesGenPipeline, NULL);
    vkDestroyPipelineLayout(ctx->secondaryDevice, ctx->forsLeavesGenPipelineLayout, NULL);
    vkDestroyShaderModule(ctx->secondaryDevice, ctx->forsLeavesGenShader, NULL);

    // FORS merkle sign pipeline
    vkDestroyDescriptorSetLayout(ctx->secondaryDevice, ctx->forsMerkleSignDescriptorSetLayout, NULL);
    vkDestroyPipeline(ctx->secondaryDevice, ctx->forsMerkleSignPipeline, NULL);
    vkDestroyPipelineLayout(ctx->secondaryDevice, ctx->forsMerkleSignPipelineLayout, NULL);
    vkDestroyShaderModule(ctx->secondaryDevice, ctx->forsMerkleSignShader, NULL);

    // primary device-wide resources
    vkDestroyCommandPool(ctx->primaryDevice, ctx->primaryCommandPool, NULL);
    vkDestroyDescriptorPool(ctx->primaryDevice, ctx->primaryDescriptorPool, NULL);
    vkDestroyDevice(ctx->primaryDevice, NULL);

    // secondary device wide resources (if not the same as the primary device)
    if (ctx->secondaryDevice != ctx->primaryDevice) {
      vkDestroyCommandPool(ctx->secondaryDevice, ctx->secondaryCommandPool, NULL);
      vkDestroyDescriptorPool(ctx->secondaryDevice, ctx->secondaryDescriptorPool, NULL);
      vkDestroyDevice(ctx->secondaryDevice, NULL);
    }

    vkDestroyInstance(ctx->instance, NULL);
    *ctx = (SlhvkContext) {0};
  }
}

int slhvkContextInit(SlhvkContext* ctxPtr) {
  VkPhysicalDevice* physicalDevices = NULL;
  SlhvkContext ctx = {0};
  int err = 0;


  /**********   Creating the vulkan instance  ************/

  VkApplicationInfo appInfo = {
    .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
    .pApplicationName = "SLHVK",
    .apiVersion = VK_API_VERSION_1_2,
  };
  VkInstanceCreateInfo instanceCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
    .pApplicationInfo = &appInfo,
  };

  // Try to enable validation layer if available.
  #ifdef DEBUG
    uint32_t numLayerProperties;
    err = vkEnumerateInstanceLayerProperties(&numLayerProperties, NULL);
    if (err) goto cleanup;

    VkLayerProperties* layerProperties = malloc(numLayerProperties * sizeof(VkLayerProperties));
    err = vkEnumerateInstanceLayerProperties(&numLayerProperties, layerProperties);
    if (err) {
      free(layerProperties);
      goto cleanup;
    }

    const char* const layers[] = {"VK_LAYER_KHRONOS_validation"};
    for (uint32_t i = 0; i < numLayerProperties; i++) {
      if (strcmp(layerProperties[i].layerName, layers[0]) == 0) {
        instanceCreateInfo.ppEnabledLayerNames = layers;
        instanceCreateInfo.enabledLayerCount = 1;
        break;
      }
    }
    free(layerProperties);
  #endif

  // enable macOS support via MoltenVK
  #ifdef __APPLE__
    const char* extensions[] = {"VK_KHR_portability_enumeration"};
    instanceCreateInfo.flags = VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR,
    instanceCreateInfo.enabledExtensionCount = sizeof(extensions) / sizeof(char*),
    instanceCreateInfo.ppEnabledExtensionNames = extensions;
  #endif

  err = vkCreateInstance(&instanceCreateInfo, NULL, &ctx.instance);
  if (err) goto cleanup;


  /**************  Find primary and secondary physical devices  *****************/

  uint32_t physicalDevicesCount = 0;
  err = vkEnumeratePhysicalDevices(ctx.instance, &physicalDevicesCount, NULL);
  if (err) goto cleanup;
  else if (physicalDevicesCount == 0) {
    err = SLHVK_ERROR_NO_COMPUTE_DEVICE;
    goto cleanup;
  }

  physicalDevices = (VkPhysicalDevice*) malloc(physicalDevicesCount * sizeof(VkPhysicalDevice));
  err = vkEnumeratePhysicalDevices(ctx.instance, &physicalDevicesCount, physicalDevices);
  if (err) return err;
  else if (physicalDevicesCount == 0) {
    err = SLHVK_ERROR_NO_COMPUTE_DEVICE;
    goto cleanup;
  }

  // Select a primary device (and secondary device too if one is available).
  for (uint32_t i = 0; i < physicalDevicesCount; i++) {
    int computeQueueFamily = findDeviceComputeQueueFamily(physicalDevices[i]);
    if (computeQueueFamily < 0) continue; // doesn't support compute shaders

    VkPhysicalDeviceProperties deviceProps;
    vkGetPhysicalDeviceProperties(physicalDevices[i], &deviceProps);

    // First, use any two devices. Then, replace the primary and secondary devices if
    // we find any superior available devices.
    if (ctx.primaryPhysicalDevice == NULL) {
      ctx.primaryPhysicalDevice = physicalDevices[i];
      ctx.primaryDeviceProperties = deviceProps;
      ctx.primaryDeviceQueueFamily = computeQueueFamily;
    } else if (ctx.secondaryPhysicalDevice == NULL) {
      ctx.secondaryPhysicalDevice = physicalDevices[i];
      ctx.secondaryDeviceProperties = deviceProps;
      ctx.secondaryDeviceQueueFamily = computeQueueFamily;
    } else if (deviceProps.limits.maxComputeSharedMemorySize > ctx.primaryDeviceProperties.limits.maxComputeSharedMemorySize) {
      ctx.primaryPhysicalDevice = physicalDevices[i];
      ctx.primaryDeviceProperties = deviceProps;
      ctx.primaryDeviceQueueFamily = computeQueueFamily;
    } else if (deviceProps.limits.maxComputeSharedMemorySize > ctx.secondaryDeviceProperties.limits.maxComputeSharedMemorySize) {
      ctx.secondaryPhysicalDevice = physicalDevices[i];
      ctx.secondaryDeviceProperties = deviceProps;
      ctx.secondaryDeviceQueueFamily = computeQueueFamily;
    }
  }

  free(physicalDevices);
  physicalDevices = NULL;

  if (ctx.primaryPhysicalDevice == NULL) {
    err = SLHVK_ERROR_NO_COMPUTE_DEVICE;
    goto cleanup;
  }

  // Only one device available. Use it as primary and secondary.
  if (ctx.secondaryPhysicalDevice == NULL) {
    ctx.secondaryPhysicalDevice = ctx.primaryPhysicalDevice;
    ctx.secondaryDeviceProperties = ctx.primaryDeviceProperties;
    ctx.secondaryDeviceQueueFamily = ctx.primaryDeviceQueueFamily;
  } else if (
    ctx.secondaryDeviceProperties.limits.maxComputeSharedMemorySize > ctx.primaryDeviceProperties.limits.maxComputeSharedMemorySize
  ) {
    // If the secondary device is better than the primary, swap them so the primary is always more powerful.
    VkPhysicalDevice           tmpDevice      = ctx.secondaryPhysicalDevice;
    VkPhysicalDeviceProperties tmpProps       = ctx.secondaryDeviceProperties;
    uint32_t                   tmpQueueFamily = ctx.secondaryDeviceQueueFamily;

    ctx.secondaryPhysicalDevice = ctx.primaryPhysicalDevice;
    ctx.secondaryDeviceProperties = ctx.primaryDeviceProperties;
    ctx.secondaryDeviceQueueFamily = ctx.primaryDeviceQueueFamily;
    ctx.primaryPhysicalDevice = tmpDevice;
    ctx.primaryDeviceProperties = tmpProps;
    ctx.primaryDeviceQueueFamily = tmpQueueFamily;
  }


  /*****************  Create logical device(s)  **********************/

  float priority = 1.0;
  VkDeviceQueueCreateInfo queueCreateInfo = {
      .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
      .queueFamilyIndex = ctx.primaryDeviceQueueFamily,
      .queueCount = 1,
      .pQueuePriorities = &priority,
  };
  VkDeviceCreateInfo deviceCreateInfo = {
      .sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
      .pQueueCreateInfos = &queueCreateInfo,
      .queueCreateInfoCount = 1,
  };
  err = vkCreateDevice(ctx.primaryPhysicalDevice, &deviceCreateInfo, NULL, &ctx.primaryDevice);
  if (err) goto cleanup;

  if (ctx.secondaryPhysicalDevice == ctx.primaryPhysicalDevice) {
    ctx.secondaryDevice = ctx.primaryDevice;
  } else {
    queueCreateInfo.queueFamilyIndex = ctx.secondaryDeviceQueueFamily;
    err = vkCreateDevice(ctx.secondaryPhysicalDevice, &deviceCreateInfo, NULL, &ctx.secondaryDevice);
    if (err) goto cleanup;
  }


  /**************  Create command pool(s)  *****************/

  VkCommandPoolCreateInfo commandPoolCreateInfo = {
      .sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
      .flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
      .queueFamilyIndex = ctx.primaryDeviceQueueFamily,
  };
  err = vkCreateCommandPool(ctx.primaryDevice, &commandPoolCreateInfo, NULL, &ctx.primaryCommandPool);
  if (err) goto cleanup;

  if (ctx.secondaryDevice == ctx.primaryDevice) {
    ctx.secondaryCommandPool = ctx.primaryCommandPool;
  } else {
    commandPoolCreateInfo.queueFamilyIndex = ctx.secondaryDeviceQueueFamily;
    err = vkCreateCommandPool(ctx.secondaryDevice, &commandPoolCreateInfo, NULL, &ctx.secondaryCommandPool);
    if (err) goto cleanup;
  }


  /*******************  Create descriptor pool(s)  **********************/

  VkDescriptorPoolSize descriptorPoolSize = {
    .type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
    .descriptorCount = MAX_DESCRIPTORS_PER_DEVICE,
  };
  VkDescriptorPoolCreateInfo descriptorPoolCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
    .maxSets = MAX_DESCRIPTOR_SETS_PER_DEVICE,
    .poolSizeCount = 1,
    .pPoolSizes = &descriptorPoolSize,
  };
  err = vkCreateDescriptorPool(ctx.primaryDevice, &descriptorPoolCreateInfo, NULL, &ctx.primaryDescriptorPool);
  if (err) goto cleanup;

  if (ctx.secondaryDevice == ctx.primaryDevice) {
    ctx.secondaryDescriptorPool = ctx.primaryDescriptorPool;
  } else {
    err = vkCreateDescriptorPool(ctx.secondaryDevice, &descriptorPoolCreateInfo, NULL, &ctx.secondaryDescriptorPool);
    if (err) goto cleanup;
  }


  /****************  Initialize buffers  ******************/

  VkBufferCreateInfo bufferCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
    .sharingMode = VK_SHARING_MODE_EXCLUSIVE, // buffers are exclusive to a single queue family at a time.
  };

  bufferCreateInfo.size = sizeof(CommonInputs);
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx.primaryDevice, &bufferCreateInfo, NULL, &ctx.primaryInputsBufferDeviceLocal);
  if (err) goto cleanup;

  bufferCreateInfo.size = sizeof(CommonInputs);
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx.primaryDevice, &bufferCreateInfo, NULL, &ctx.primaryInputsBufferHostVisible);
  if (err) goto cleanup;

  bufferCreateInfo.size = WOTS_CHAIN_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
  err = vkCreateBuffer(ctx.primaryDevice, &bufferCreateInfo, NULL, &ctx.primaryWotsChainBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = XMSS_NODES_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
  err = vkCreateBuffer(ctx.primaryDevice, &bufferCreateInfo, NULL, &ctx.primaryXmssNodesBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = XMSS_MESSAGES_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx.primaryDevice, &bufferCreateInfo, NULL, &ctx.primaryXmssMessagesBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = FORS_PUBKEY_STAGING_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx.primaryDevice, &bufferCreateInfo, NULL, &ctx.primaryForsPubkeyStagingBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = HYPERTREE_SIGNATURE_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx.primaryDevice, &bufferCreateInfo, NULL, &ctx.primaryHypertreeSignatureBufferDeviceLocal);
  if (err) goto cleanup;

  bufferCreateInfo.size = HYPERTREE_SIGNATURE_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx.primaryDevice, &bufferCreateInfo, NULL, &ctx.primaryHypertreeSignatureBufferHostVisible);
  if (err) goto cleanup;

  /**** Secondary device buffers ****/

  bufferCreateInfo.size = sizeof(CommonInputs);
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx.secondaryDevice, &bufferCreateInfo, NULL, &ctx.secondaryInputsBufferDeviceLocal);
  if (err) goto cleanup;

  bufferCreateInfo.size = sizeof(CommonInputs);
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx.secondaryDevice, &bufferCreateInfo, NULL, &ctx.secondaryInputsBufferHostVisible);
  if (err) goto cleanup;

  bufferCreateInfo.size = FORS_MESSAGE_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx.secondaryDevice, &bufferCreateInfo, NULL, &ctx.secondaryForsMessageBufferDeviceLocal);
  if (err) goto cleanup;

  bufferCreateInfo.size = FORS_MESSAGE_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx.secondaryDevice, &bufferCreateInfo, NULL, &ctx.secondaryForsMessageBufferHostVisible);
  if (err) goto cleanup;

  bufferCreateInfo.size = FORS_NODES_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx.secondaryDevice, &bufferCreateInfo, NULL, &ctx.secondaryForsNodesBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = FORS_SIGNATURE_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx.secondaryDevice, &bufferCreateInfo, NULL, &ctx.secondaryForsSignatureBufferDeviceLocal);
  if (err) goto cleanup;

  bufferCreateInfo.size = FORS_SIGNATURE_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx.secondaryDevice, &bufferCreateInfo, NULL, &ctx.secondaryForsSignatureBufferHostVisible);
  if (err) goto cleanup;

  bufferCreateInfo.size = FORS_ROOTS_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx.secondaryDevice, &bufferCreateInfo, NULL, &ctx.secondaryForsRootsBuffer);
  if (err) goto cleanup;


  /*******************  Allocate primary device local memory  **********************/

  #define PRIMARY_DEVICE_LOCAL_BUFFER_COUNT 5
  VkBuffer primaryDeviceLocalBuffers[PRIMARY_DEVICE_LOCAL_BUFFER_COUNT] = {
    ctx.primaryInputsBufferDeviceLocal,
    ctx.primaryWotsChainBuffer,
    ctx.primaryXmssNodesBuffer,
    ctx.primaryXmssMessagesBuffer,
    ctx.primaryHypertreeSignatureBufferDeviceLocal,
  };
  VkDeviceMemory* primaryDeviceLocalMemories[PRIMARY_DEVICE_LOCAL_BUFFER_COUNT] = {
    &ctx.primaryInputsBufferDeviceLocalMemory,
    &ctx.primaryWotsChainBufferMemory,
    &ctx.primaryXmssNodesBufferMemory,
    &ctx.primaryXmssMessagesBufferMemory,
    &ctx.primaryHypertreeSignatureBufferDeviceLocalMemory,
  };

  for (uint32_t i = 0; i < PRIMARY_DEVICE_LOCAL_BUFFER_COUNT; i++) {
    err = allocateBufferMemory(
      ctx.primaryDevice,
      ctx.primaryPhysicalDevice,
      primaryDeviceLocalBuffers[i],
      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
      &ctx.primaryDeviceLocalMemoryFlags, // TODO: assumes buffers end up with the same memory type
      primaryDeviceLocalMemories[i]
    );
    if (err) goto cleanup;
  }


  /*******************  Allocate secondary device local memory  **********************/

  #define SECONDARY_DEVICE_LOCAL_BUFFER_COUNT 4
  VkBuffer secondaryDeviceLocalBuffers[SECONDARY_DEVICE_LOCAL_BUFFER_COUNT] = {
    ctx.secondaryInputsBufferDeviceLocal,
    ctx.secondaryForsMessageBufferDeviceLocal,
    ctx.secondaryForsNodesBuffer,
    ctx.secondaryForsSignatureBufferDeviceLocal,
  };
  VkDeviceMemory* secondaryDeviceLocalMemories[SECONDARY_DEVICE_LOCAL_BUFFER_COUNT] = {
    &ctx.secondaryInputsBufferDeviceLocalMemory,
    &ctx.secondaryForsMessageBufferDeviceLocalMemory,
    &ctx.secondaryForsNodesBufferMemory,
    &ctx.secondaryForsSignatureBufferDeviceLocalMemory,
  };

  for (uint32_t i = 0; i < SECONDARY_DEVICE_LOCAL_BUFFER_COUNT; i++) {
    err = allocateBufferMemory(
      ctx.secondaryDevice,
      ctx.secondaryPhysicalDevice,
      secondaryDeviceLocalBuffers[i],
      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
      &ctx.secondaryDeviceLocalMemoryFlags, // TODO: assumes buffers end up with the same memory type
      secondaryDeviceLocalMemories[i]
    );
    if (err) goto cleanup;
  }


  /*******************  Allocate primary host visible memory  **********************/

  // Only allocate if device local memory isn't already host-visible.
  if (!(ctx.primaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)) {
    err = allocateBufferMemory(
      ctx.primaryDevice,
      ctx.primaryPhysicalDevice,
      ctx.primaryInputsBufferHostVisible,
      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
      &ctx.primaryDeviceHostVisibleMemoryFlags,
      &ctx.primaryInputsBufferHostVisibleMemory
    );
    if (err) goto cleanup;

    err = allocateBufferMemory(
      ctx.primaryDevice,
      ctx.primaryPhysicalDevice,
      ctx.primaryHypertreeSignatureBufferHostVisible,
      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
      &ctx.primaryDeviceHostVisibleMemoryFlags,
      &ctx.primaryHypertreeSignatureBufferHostVisibleMemory
    );
    if (err) goto cleanup;
  }

  err = allocateBufferMemory(
    ctx.primaryDevice,
    ctx.primaryPhysicalDevice,
    ctx.primaryForsPubkeyStagingBuffer,
    VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
    &ctx.primaryDeviceHostVisibleMemoryFlags,
    &ctx.primaryForsPubkeyStagingBufferMemory
  );
  if (err) goto cleanup;


  /*******************  Allocate secondary host visible memory  **********************/

  // Only allocate if device local memory isn't already host-visible.
  if (!(ctx.secondaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)) {
    err = allocateBufferMemory(
      ctx.secondaryDevice,
      ctx.secondaryPhysicalDevice,
      ctx.secondaryInputsBufferHostVisible,
      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
      &ctx.secondaryDeviceHostVisibleMemoryFlags,
      &ctx.secondaryInputsBufferHostVisibleMemory
    );
    if (err) goto cleanup;

    err = allocateBufferMemory(
      ctx.secondaryDevice,
      ctx.secondaryPhysicalDevice,
      ctx.secondaryForsMessageBufferHostVisible,
      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
      &ctx.secondaryDeviceHostVisibleMemoryFlags,
      &ctx.secondaryForsMessageBufferHostVisibleMemory
    );
    if (err) goto cleanup;

    err = allocateBufferMemory(
      ctx.secondaryDevice,
      ctx.secondaryPhysicalDevice,
      ctx.secondaryForsSignatureBufferHostVisible,
      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
      &ctx.secondaryDeviceHostVisibleMemoryFlags,
      &ctx.secondaryForsSignatureBufferHostVisibleMemory
    );
    if (err) goto cleanup;
  }

  err = allocateBufferMemory(
    ctx.secondaryDevice,
    ctx.secondaryPhysicalDevice,
    ctx.secondaryForsRootsBuffer,
    VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
    &ctx.secondaryDeviceHostVisibleMemoryFlags,
    &ctx.secondaryForsRootsBufferMemory
  );
  if (err) goto cleanup;


  /*******************  Define descriptor set layouts  **********************/

  err = setupDescriptorSetLayout(
    ctx.primaryDevice,
    WOTS_TIPS_PRECOMPUTE_PIPELINE_DESCRIPTOR_COUNT,
    &ctx.wotsTipsPrecomputeDescriptorSetLayout
  );
  if (err) goto cleanup;

  err = setupDescriptorSetLayout(
    ctx.primaryDevice,
    XMSS_LEAVES_PRECOMPUTE_PIPELINE_DESCRIPTOR_COUNT,
    &ctx.xmssLeavesPrecomputeDescriptorSetLayout
  );
  if (err) goto cleanup;

  err = setupDescriptorSetLayout(
    ctx.primaryDevice,
    XMSS_MERKLE_SIGN_PIPELINE_DESCRIPTOR_COUNT,
    &ctx.xmssMerkleSignDescriptorSetLayout
  );
  if (err) goto cleanup;

  err = setupDescriptorSetLayout(
    ctx.primaryDevice,
    WOTS_SIGN_PIPELINE_DESCRIPTOR_COUNT,
    &ctx.wotsSignDescriptorSetLayout
  );
  if (err) goto cleanup;

  err = setupDescriptorSetLayout(
    ctx.secondaryDevice,
    FORS_LEAVES_GEN_PIPELINE_DESCRIPTOR_COUNT,
    &ctx.forsLeavesGenDescriptorSetLayout
  );
  if (err) goto cleanup;

  err = setupDescriptorSetLayout(
    ctx.secondaryDevice,
    FORS_MERKLE_SIGN_PIPELINE_DESCRIPTOR_COUNT,
    &ctx.forsMerkleSignDescriptorSetLayout
  );
  if (err) goto cleanup;


  /*******************  Define pipeline layouts  **********************/

  VkPipelineLayoutCreateInfo pipelineLayoutCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
    .setLayoutCount = 1,
  };

  pipelineLayoutCreateInfo.pSetLayouts = &ctx.wotsTipsPrecomputeDescriptorSetLayout,
  err = vkCreatePipelineLayout(
    ctx.primaryDevice,
    &pipelineLayoutCreateInfo,
    NULL,
    &ctx.wotsTipsPrecomputePipelineLayout
  );
  if (err) goto cleanup;

  pipelineLayoutCreateInfo.pSetLayouts = &ctx.xmssLeavesPrecomputeDescriptorSetLayout,
  err = vkCreatePipelineLayout(
    ctx.primaryDevice,
    &pipelineLayoutCreateInfo,
    NULL,
    &ctx.xmssLeavesPrecomputePipelineLayout
  );
  if (err) goto cleanup;

  pipelineLayoutCreateInfo.pSetLayouts = &ctx.xmssMerkleSignDescriptorSetLayout,
  err = vkCreatePipelineLayout(
    ctx.primaryDevice,
    &pipelineLayoutCreateInfo,
    NULL,
    &ctx.xmssMerkleSignPipelineLayout
  );
  if (err) goto cleanup;

  pipelineLayoutCreateInfo.pSetLayouts = &ctx.wotsSignDescriptorSetLayout,
  err = vkCreatePipelineLayout(
    ctx.primaryDevice,
    &pipelineLayoutCreateInfo,
    NULL,
    &ctx.wotsSignPipelineLayout
  );
  if (err) goto cleanup;

  pipelineLayoutCreateInfo.pSetLayouts = &ctx.forsLeavesGenDescriptorSetLayout,
  err = vkCreatePipelineLayout(
    ctx.secondaryDevice,
    &pipelineLayoutCreateInfo,
    NULL,
    &ctx.forsLeavesGenPipelineLayout
  );
  if (err) goto cleanup;

  pipelineLayoutCreateInfo.pSetLayouts = &ctx.forsMerkleSignDescriptorSetLayout,
  err = vkCreatePipelineLayout(
    ctx.secondaryDevice,
    &pipelineLayoutCreateInfo,
    NULL,
    &ctx.forsMerkleSignPipelineLayout
  );
  if (err) goto cleanup;


  /*******************  Allocate primary descriptor sets  **********************/

  VkDescriptorSetAllocateInfo descriptorSetAllocateInfo = {
    .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
    .descriptorPool = ctx.primaryDescriptorPool, // pool to allocate from.
    .descriptorSetCount = 1,                     // allocate a single descriptor set per pipeline.
  };

  descriptorSetAllocateInfo.pSetLayouts = &ctx.wotsTipsPrecomputeDescriptorSetLayout;
  err = vkAllocateDescriptorSets(ctx.primaryDevice, &descriptorSetAllocateInfo, &ctx.wotsTipsPrecomputeDescriptorSet);
  if (err) goto cleanup;

  descriptorSetAllocateInfo.pSetLayouts = &ctx.xmssLeavesPrecomputeDescriptorSetLayout;
  err = vkAllocateDescriptorSets(ctx.primaryDevice, &descriptorSetAllocateInfo, &ctx.xmssLeavesPrecomputeDescriptorSet);
  if (err) goto cleanup;

  descriptorSetAllocateInfo.pSetLayouts = &ctx.xmssMerkleSignDescriptorSetLayout;
  err = vkAllocateDescriptorSets(ctx.primaryDevice, &descriptorSetAllocateInfo, &ctx.xmssMerkleSignDescriptorSet);
  if (err) goto cleanup;

  descriptorSetAllocateInfo.pSetLayouts = &ctx.wotsSignDescriptorSetLayout;
  err = vkAllocateDescriptorSets(ctx.primaryDevice, &descriptorSetAllocateInfo, &ctx.wotsSignDescriptorSet);
  if (err) goto cleanup;


  /*******************  Allocate secondary descriptor sets  **********************/

  descriptorSetAllocateInfo.descriptorPool = ctx.secondaryDescriptorPool;

  descriptorSetAllocateInfo.pSetLayouts = &ctx.forsLeavesGenDescriptorSetLayout;
  err = vkAllocateDescriptorSets(ctx.secondaryDevice, &descriptorSetAllocateInfo, &ctx.forsLeavesGenDescriptorSet);
  if (err) goto cleanup;

  descriptorSetAllocateInfo.pSetLayouts = &ctx.forsMerkleSignDescriptorSetLayout;
  err = vkAllocateDescriptorSets(ctx.secondaryDevice, &descriptorSetAllocateInfo, &ctx.forsMerkleSignDescriptorSet);
  if (err) goto cleanup;


  /*******************  Bind primary device buffers to descriptor sets  **********************/

  VkBuffer wotsTipsPrecomputeBuffers[WOTS_TIPS_PRECOMPUTE_PIPELINE_DESCRIPTOR_COUNT] = {
    ctx.primaryInputsBufferDeviceLocal,
    ctx.primaryWotsChainBuffer,
  };
  bindBuffersToDescriptorSet(
    ctx.primaryDevice,
    wotsTipsPrecomputeBuffers,
    WOTS_TIPS_PRECOMPUTE_PIPELINE_DESCRIPTOR_COUNT,
    ctx.wotsTipsPrecomputeDescriptorSet
  );

  VkBuffer xmssLeavesPrecomputeBuffers[XMSS_LEAVES_PRECOMPUTE_PIPELINE_DESCRIPTOR_COUNT] = {
    ctx.primaryInputsBufferDeviceLocal,
    ctx.primaryWotsChainBuffer,
    ctx.primaryXmssNodesBuffer,
  };
  bindBuffersToDescriptorSet(
    ctx.primaryDevice,
    xmssLeavesPrecomputeBuffers,
    XMSS_LEAVES_PRECOMPUTE_PIPELINE_DESCRIPTOR_COUNT,
    ctx.xmssLeavesPrecomputeDescriptorSet
  );

  VkBuffer xmssMerkleSignBuffers[XMSS_MERKLE_SIGN_PIPELINE_DESCRIPTOR_COUNT] = {
    ctx.primaryInputsBufferDeviceLocal,
    ctx.primaryXmssNodesBuffer,
    ctx.primaryHypertreeSignatureBufferDeviceLocal,
    ctx.primaryXmssMessagesBuffer,
  };
  bindBuffersToDescriptorSet(
    ctx.primaryDevice,
    xmssMerkleSignBuffers,
    XMSS_MERKLE_SIGN_PIPELINE_DESCRIPTOR_COUNT,
    ctx.xmssMerkleSignDescriptorSet
  );

  VkBuffer wotsSignBuffers[WOTS_SIGN_PIPELINE_DESCRIPTOR_COUNT] = {
    ctx.primaryInputsBufferDeviceLocal,
    ctx.primaryHypertreeSignatureBufferDeviceLocal,
    ctx.primaryXmssMessagesBuffer,
  };
  bindBuffersToDescriptorSet(
    ctx.primaryDevice,
    wotsSignBuffers,
    WOTS_SIGN_PIPELINE_DESCRIPTOR_COUNT,
    ctx.wotsSignDescriptorSet
  );

  /*******************  Bind secondary device buffers to descriptor sets  **********************/

  VkBuffer forsLeavesGenBuffers[FORS_LEAVES_GEN_PIPELINE_DESCRIPTOR_COUNT] = {
    ctx.secondaryInputsBufferDeviceLocal,
    ctx.secondaryForsMessageBufferDeviceLocal,
    ctx.secondaryForsNodesBuffer,
    ctx.secondaryForsSignatureBufferDeviceLocal,
  };
  bindBuffersToDescriptorSet(
    ctx.secondaryDevice,
    forsLeavesGenBuffers,
    FORS_LEAVES_GEN_PIPELINE_DESCRIPTOR_COUNT,
    ctx.forsLeavesGenDescriptorSet
  );

  VkBuffer forsMerkleSignBuffers[FORS_MERKLE_SIGN_PIPELINE_DESCRIPTOR_COUNT] = {
    ctx.secondaryInputsBufferDeviceLocal,
    ctx.secondaryForsMessageBufferDeviceLocal,
    ctx.secondaryForsNodesBuffer,
    ctx.secondaryForsSignatureBufferDeviceLocal,
  };
  bindBuffersToDescriptorSet(
    ctx.secondaryDevice,
    forsMerkleSignBuffers,
    FORS_MERKLE_SIGN_PIPELINE_DESCRIPTOR_COUNT,
    ctx.forsMerkleSignDescriptorSet
  );

  /*******************  Build shader modules  **********************/

  VkShaderModuleCreateInfo shaderCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
  };

  shaderCreateInfo.pCode = (uint32_t*) wots_tips_precompute_spv,
  shaderCreateInfo.codeSize = wots_tips_precompute_spv_len,
  err = vkCreateShaderModule(ctx.primaryDevice, &shaderCreateInfo, NULL, &ctx.wotsTipsPrecomputeShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) xmss_leaves_precompute_spv,
  shaderCreateInfo.codeSize = xmss_leaves_precompute_spv_len,
  err = vkCreateShaderModule(ctx.primaryDevice, &shaderCreateInfo, NULL, &ctx.xmssLeavesPrecomputeShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) xmss_merkle_sign_spv,
  shaderCreateInfo.codeSize = xmss_merkle_sign_spv_len,
  err = vkCreateShaderModule(ctx.primaryDevice, &shaderCreateInfo, NULL, &ctx.xmssMerkleSignShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) wots_sign_spv,
  shaderCreateInfo.codeSize = wots_sign_spv_len,
  err = vkCreateShaderModule(ctx.primaryDevice, &shaderCreateInfo, NULL, &ctx.wotsSignShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) fors_leaves_gen_spv,
  shaderCreateInfo.codeSize = fors_leaves_gen_spv_len,
  err = vkCreateShaderModule(ctx.secondaryDevice, &shaderCreateInfo, NULL, &ctx.forsLeavesGenShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) fors_merkle_sign_spv,
  shaderCreateInfo.codeSize = fors_merkle_sign_spv_len,
  err = vkCreateShaderModule(ctx.secondaryDevice, &shaderCreateInfo, NULL, &ctx.forsMerkleSignShader);
  if (err) goto cleanup;


  /**********  Define specialization constants  **********/

  const uint32_t specializationConstants[SPEC_CONSTANTS_COUNT] = {
    SLHVK_DEFAULT_WORK_GROUP_SIZE,
    HASH_WORDS,
    FORS_TREE_HEIGHT,
    FORS_TREE_COUNT,
    LOG_W,
    WOTS_CHAIN_COUNT1,
    WOTS_CHAIN_COUNT2,
    XMSS_HEIGHT,
    HYPERTREE_LAYERS,
  };

  VkSpecializationMapEntry specConstEntries[SPEC_CONSTANTS_COUNT];
  for (uint32_t i = 0; i < SPEC_CONSTANTS_COUNT; i++) {
    specConstEntries[i] = (VkSpecializationMapEntry) {
      .constantID = i,
      .offset = i * sizeof(uint32_t),
      .size = sizeof(uint32_t),
    };
  }
  VkSpecializationInfo specializationInfo = {
    .mapEntryCount = SPEC_CONSTANTS_COUNT,
    .pMapEntries = specConstEntries,
    .dataSize = SPEC_CONSTANTS_COUNT * sizeof(uint32_t),
    .pData = (const void*) specializationConstants,
  };


  /**********  Create pipelines  **********/

  VkPipelineShaderStageCreateInfo shaderStageCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
    .stage = VK_SHADER_STAGE_COMPUTE_BIT,
    .pName = "main",
    .pSpecializationInfo = &specializationInfo,
  };
  VkComputePipelineCreateInfo pipelineCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO,
    .stage = shaderStageCreateInfo,
  };

  pipelineCreateInfo.stage.module = ctx.wotsTipsPrecomputeShader;
  pipelineCreateInfo.layout       = ctx.wotsTipsPrecomputePipelineLayout;
  err = vkCreateComputePipelines(
    ctx.primaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx.wotsTipsPrecomputePipeline
  );
  if (err) goto cleanup;

  pipelineCreateInfo.stage.module = ctx.xmssLeavesPrecomputeShader;
  pipelineCreateInfo.layout       = ctx.xmssLeavesPrecomputePipelineLayout;
  err = vkCreateComputePipelines(
    ctx.primaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx.xmssLeavesPrecomputePipeline
  );
  if (err) goto cleanup;

  pipelineCreateInfo.stage.module = ctx.xmssMerkleSignShader;
  pipelineCreateInfo.layout       = ctx.xmssMerkleSignPipelineLayout;
  err = vkCreateComputePipelines(
    ctx.primaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx.xmssMerkleSignPipeline
  );
  if (err) goto cleanup;

  pipelineCreateInfo.stage.module = ctx.wotsSignShader;
  pipelineCreateInfo.layout       = ctx.wotsSignPipelineLayout;
  err = vkCreateComputePipelines(
    ctx.primaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx.wotsSignPipeline
  );
  if (err) goto cleanup;

  pipelineCreateInfo.stage.module = ctx.forsLeavesGenShader;
  pipelineCreateInfo.layout       = ctx.forsLeavesGenPipelineLayout;
  err = vkCreateComputePipelines(
    ctx.secondaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx.forsLeavesGenPipeline
  );
  if (err) goto cleanup;

  pipelineCreateInfo.stage.module = ctx.forsMerkleSignShader;
  pipelineCreateInfo.layout       = ctx.forsMerkleSignPipelineLayout;
  err = vkCreateComputePipelines(
    ctx.secondaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx.forsMerkleSignPipeline
  );
  if (err) goto cleanup;


  /*****************  Create primary device command buffers ******************/

  #define PRIMARY_COMMAND_BUFFER_COUNT 2
  VkCommandBufferAllocateInfo cmdBufAllocInfo = {
    .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
    .commandPool = ctx.primaryCommandPool,
    .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
    .commandBufferCount = PRIMARY_COMMAND_BUFFER_COUNT,
  };
  VkCommandBuffer primaryCmdBufs[PRIMARY_COMMAND_BUFFER_COUNT];
  err = vkAllocateCommandBuffers(ctx.primaryDevice, &cmdBufAllocInfo, primaryCmdBufs);
  if (err) goto cleanup;

  ctx.primaryHypertreePresignCommandBuffer = primaryCmdBufs[0];
  ctx.primaryHypertreeFinishCommandBuffer  = primaryCmdBufs[1];


  /*****************  Create secondary device command buffers ******************/

  cmdBufAllocInfo.commandPool = ctx.secondaryCommandPool;
  cmdBufAllocInfo.commandBufferCount = 1;
  err = vkAllocateCommandBuffers(ctx.secondaryDevice, &cmdBufAllocInfo, &ctx.secondaryForsCommandBuffer);
  if (err) goto cleanup;


  /**************  Fill the first primary device command buffer  ***************/

  VkCommandBufferBeginInfo cmdBufBeginInfo = {
    .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
  };
  err = vkBeginCommandBuffer(ctx.primaryHypertreePresignCommandBuffer, &cmdBufBeginInfo);
  if (err) goto cleanup;

  // Copy from a host-visible buffer if the device-local buffer isn't also host-visible.
  if ((ctx.primaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) == 0) {
    VkBufferCopy regions = { .size = sizeof(CommonInputs) };
    vkCmdCopyBuffer(
      ctx.primaryHypertreePresignCommandBuffer,
      ctx.primaryInputsBufferHostVisible, // src
      ctx.primaryInputsBufferDeviceLocal, // dest
      1, // region count
      &regions // regions
    );
  }

  // Bind and dispatch the WOTS tips precompute shader.
  vkCmdBindPipeline(
    ctx.primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx.wotsTipsPrecomputePipeline
  );
  vkCmdBindDescriptorSets(
    ctx.primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx.wotsTipsPrecomputePipelineLayout,
    0, // set number of first descriptor_set to be bound
    1, // number of descriptor sets
    &ctx.wotsTipsPrecomputeDescriptorSet,
    0,  // offset count
    NULL // offsets array
  );
  vkCmdDispatch(
    ctx.primaryHypertreePresignCommandBuffer,
    numWorkGroups(HYPERTREE_LAYERS * XMSS_LEAVES * WOTS_CHAIN_COUNT),
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  // Specify that the XMSS leaf precompute shader depends on the WOTS chain buffer
  // output from the WOTS tip precompute shader.
  VkMemoryBarrier xmssLeavesPrecomputeMemoryBarrier = {
    .sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER,
    .srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT,
    .dstAccessMask = VK_ACCESS_SHADER_READ_BIT,
  };
  vkCmdPipelineBarrier(
    ctx.primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    0, // flags
    1, &xmssLeavesPrecomputeMemoryBarrier, // VkMemoryBarrier[]
    0, NULL,                               // VkBufferMemoryBarrier[]
    0, NULL                                // VkImageMemoryBarrier[]
  );

  // Bind and dispatch the XMSS leaves precompute shader.
  vkCmdBindPipeline(
    ctx.primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx.xmssLeavesPrecomputePipeline
  );
  vkCmdBindDescriptorSets(
    ctx.primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx.xmssLeavesPrecomputePipelineLayout,
    0, // set number of first descriptor_set to be bound
    1, // number of descriptor sets
    &ctx.xmssLeavesPrecomputeDescriptorSet,
    0,  // offset count
    NULL // offsets array
  );
  vkCmdDispatch(
    ctx.primaryHypertreePresignCommandBuffer,
    numWorkGroups(HYPERTREE_LAYERS * XMSS_LEAVES),
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );


  // Specify that the XMSS sign shader depends on the XMSS nodes
  // buffer output from the XMSS leaves precompute shader.
  VkMemoryBarrier xmssMerkleSignMemoryBarrier = {
    .sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER,
    .srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT,
    .dstAccessMask = VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_SHADER_WRITE_BIT,
  };
  vkCmdPipelineBarrier(
    ctx.primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    0, // flags
    1, &xmssMerkleSignMemoryBarrier, // VkMemoryBarrier[]
    0, NULL,                         // VkBufferMemoryBarrier[]
    0, NULL                          // VkImageMemoryBarrier[]
  );

  // Bind and dispatch the XMSS merkle sign precompute shader.
  vkCmdBindPipeline(
    ctx.primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx.xmssMerkleSignPipeline
  );
  vkCmdBindDescriptorSets(
    ctx.primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx.xmssMerkleSignPipelineLayout,
    0, // set number of first descriptor_set to be bound
    1, // number of descriptor sets
    &ctx.xmssMerkleSignDescriptorSet,
    0,  // offset count
    NULL // offsets array
  );
  vkCmdDispatch(
    ctx.primaryHypertreePresignCommandBuffer,
    HYPERTREE_LAYERS, // One work group per XMSS tree
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  err = vkEndCommandBuffer(ctx.primaryHypertreePresignCommandBuffer);
  if (err) goto cleanup;


  /**************  Fill the secondary command buffer *****************/

  err = vkBeginCommandBuffer(ctx.secondaryForsCommandBuffer, &cmdBufBeginInfo);
  if (err) goto cleanup;

  // Copy from host-visible buffers if the device-local buffer isn't also host-visible.
  if ((ctx.secondaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) == 0) {
    VkBufferCopy regions = { .size = sizeof(CommonInputs) };
    vkCmdCopyBuffer(
      ctx.secondaryForsCommandBuffer,
      ctx.secondaryInputsBufferHostVisible, // src
      ctx.secondaryInputsBufferDeviceLocal, // dest
      1, // region count
      &regions // regions
    );

    regions.size = FORS_MESSAGE_BUFFER_SIZE;
    vkCmdCopyBuffer(
      ctx.secondaryForsCommandBuffer,
      ctx.secondaryForsMessageBufferHostVisible, // src
      ctx.secondaryForsMessageBufferDeviceLocal, // dest
      1, // region count
      &regions // regions
    );
  }

  // Bind and dispatch the FORS leaves gen shader.
  vkCmdBindPipeline(
    ctx.secondaryForsCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx.forsLeavesGenPipeline
  );
  vkCmdBindDescriptorSets(
    ctx.secondaryForsCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx.forsLeavesGenPipelineLayout,
    0, // set number of first descriptor_set to be bound
    1, // number of descriptor sets
    &ctx.forsLeavesGenDescriptorSet,
    0,  // offset count
    NULL // offsets array
  );
  vkCmdDispatch(
    ctx.secondaryForsCommandBuffer,
    numWorkGroups(FORS_TREE_COUNT * FORS_LEAVES_COUNT), // One thread per FORS leaf node
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  // Specify that the FORS merkle sign shader depends on the FORS leaf buffer
  // output from the FORS leaves gen shader.
  VkMemoryBarrier forsMerkleSignMemoryBarrier = {
    .sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER,
    .srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT,
    .dstAccessMask = VK_ACCESS_SHADER_READ_BIT,
  };
  vkCmdPipelineBarrier(
    ctx.secondaryForsCommandBuffer,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    0, // flags
    1, &forsMerkleSignMemoryBarrier, // VkMemoryBarrier[]
    0, NULL,                         // VkBufferMemoryBarrier[]
    0, NULL                          // VkImageMemoryBarrier[]
  );

  // Bind and dispatch the FORS merkle sign shader.
  vkCmdBindPipeline(
    ctx.secondaryForsCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx.forsMerkleSignPipeline
  );
  vkCmdBindDescriptorSets(
    ctx.secondaryForsCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx.forsMerkleSignPipelineLayout,
    0, // set number of first descriptor_set to be bound
    1, // number of descriptor sets
    &ctx.forsMerkleSignDescriptorSet,
    0,  // offset count
    NULL // offsets array
  );
  vkCmdDispatch(
    ctx.secondaryForsCommandBuffer,
    FORS_TREE_COUNT, // One work group per FORS tree
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  // Copy to host-visible buffer if the device-local buffer isn't also host-visible.
  if ((ctx.secondaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) == 0) {
    VkBufferCopy regions = { .size = FORS_SIGNATURE_SIZE };
    vkCmdCopyBuffer(
      ctx.secondaryForsCommandBuffer,
      ctx.secondaryForsSignatureBufferDeviceLocal, // src
      ctx.secondaryForsSignatureBufferHostVisible, // dest
      1, // region count
      &regions // regions
    );
  }

  // Copy each of the computed FORS tree root hashes to a host-visible buffer.
  VkBufferCopy forsRootsCopyRegions[FORS_TREE_COUNT];
  for (uint32_t i = 0; i < FORS_TREE_COUNT; i++) {
    forsRootsCopyRegions[i] = (VkBufferCopy) {
      .srcOffset = i * FORS_LEAVES_COUNT * N,
      .dstOffset = i * N,
      .size = N,
    };
  }
  vkCmdCopyBuffer(
    ctx.secondaryForsCommandBuffer,
    ctx.secondaryForsNodesBuffer, // src
    ctx.secondaryForsRootsBuffer, // dest
    FORS_TREE_COUNT, // region count
    forsRootsCopyRegions
  );

  err = vkEndCommandBuffer(ctx.secondaryForsCommandBuffer);
  if (err) goto cleanup;


  /*************  Fill the second primary device command buffer  **************/

  err = vkBeginCommandBuffer(ctx.primaryHypertreeFinishCommandBuffer, &cmdBufBeginInfo);
  if (err) goto cleanup;

  // Copy the FORS pubkey to the XMSS messages buffer
  VkBufferCopy regions = {
    .size = FORS_PUBKEY_STAGING_BUFFER_SIZE,
    .srcOffset = 0,
    .dstOffset = 0,
  };
  vkCmdCopyBuffer(
    ctx.primaryHypertreeFinishCommandBuffer,
    ctx.primaryForsPubkeyStagingBuffer, // src
    ctx.primaryXmssMessagesBuffer, // dest
    1, // region count
    &regions
  );

  // Bind and dispatch the final WOTS signing shader.
  vkCmdBindPipeline(
    ctx.primaryHypertreeFinishCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx.wotsSignPipeline
  );
  vkCmdBindDescriptorSets(
    ctx.primaryHypertreeFinishCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx.wotsSignPipelineLayout,
    0, // set number of first descriptor_set to be bound
    1, // number of descriptor sets
    &ctx.wotsSignDescriptorSet,
    0,  // offset count
    NULL // offsets array
  );
  vkCmdDispatch(
    ctx.primaryHypertreeFinishCommandBuffer,
    numWorkGroups(HYPERTREE_LAYERS * WOTS_CHAIN_COUNT), // One thread per signing chain
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  // Copy to a host-visible buffer if the device-local buffer isn't also host-visible.
  if ((ctx.primaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) == 0) {
    VkBufferCopy regions = { .size = HYPERTREE_SIGNATURE_SIZE };
    vkCmdCopyBuffer(
      ctx.primaryHypertreeFinishCommandBuffer,
      ctx.primaryHypertreeSignatureBufferDeviceLocal, // src
      ctx.primaryHypertreeSignatureBufferHostVisible, // dest
      1, // region count
      &regions // regions
    );
  }

  err = vkEndCommandBuffer(ctx.primaryHypertreeFinishCommandBuffer);
  if (err) goto cleanup;

  *ctxPtr = ctx;
  return 0;

cleanup:
  free(physicalDevices);
  slhvkContextFree(&ctx);
  return err;
}

static void prepstate(ShaContext* shaCtx, const uint8_t pkSeed[N]) {
  uint8_t block[64] = {0};
  memcpy(block, pkSeed, N);
  sha256_init(shaCtx);
  sha256_update(shaCtx, block, 64);
}

int slhvkSignPure(
  SlhvkContext* ctx,
  const uint8_t skSeed[N],
  const uint8_t skPrf[N],
  const uint8_t pkSeed[N],
  const uint8_t pkRoot[N],
  const uint8_t addrnd[N],
  const uint8_t* contextString,
  uint8_t contextStringSize,
  const uint8_t* rawMessage,
  size_t rawMessageSize,
  uint8_t signatureOutput[SLH_DSA_SIGNATURE_SIZE]
) {
  // Deterministic mode
  if (addrnd == NULL) addrnd = pkSeed;

  uint8_t randomizer[N];
  slhvkMessagePrf(
    skPrf,
    addrnd,
    contextString,
    contextStringSize,
    rawMessage,
    rawMessageSize,
    randomizer
  );

  uint32_t forsIndices[FORS_TREE_COUNT];
  uint64_t treeAddress;
  uint32_t signingKeypairAddress;
  slhvkDigestAndSplitMsg(
    randomizer,
    pkSeed,
    pkRoot,
    contextString,
    contextStringSize,
    rawMessage,
    rawMessageSize,
    forsIndices,
    &treeAddress,
    &signingKeypairAddress
  );

  VkQueue primaryQueue;
  vkGetDeviceQueue(ctx->primaryDevice, ctx->primaryDeviceQueueFamily, 0, &primaryQueue);

  VkQueue secondaryQueue;
  if (ctx->secondaryDevice == ctx->primaryDevice) {
    secondaryQueue = primaryQueue;
  } else {
    vkGetDeviceQueue(ctx->secondaryDevice, ctx->secondaryDeviceQueueFamily, 0, &secondaryQueue);
  }

  // We create two fences to await the final outputs on each device.
  VkFence primaryFence = NULL;
  VkFence secondaryFence = NULL;

  VkFenceCreateInfo fenceCreateInfo = { .sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO };
  int err = vkCreateFence(ctx->primaryDevice, &fenceCreateInfo, NULL, &primaryFence);
  if (err) goto cleanup;
  err = vkCreateFence(ctx->secondaryDevice, &fenceCreateInfo, NULL, &secondaryFence);
  if (err) goto cleanup;

  // Prehash the pk_seed value.
  ShaContext shaCtxInitial;
  prepstate(&shaCtxInitial, pkSeed);

  // Write inputs straight to the device local buffers if we can.
  VkDeviceMemory primaryInputsMemory = (ctx->primaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)
    ? ctx->primaryInputsBufferDeviceLocalMemory
    : ctx->primaryInputsBufferHostVisibleMemory;
  VkDeviceMemory secondaryInputsMemory = (ctx->secondaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)
    ? ctx->secondaryInputsBufferDeviceLocalMemory
    : ctx->secondaryInputsBufferHostVisibleMemory;

  VkDeviceMemory memories[2] = { primaryInputsMemory, secondaryInputsMemory };
  VkDevice       devices[2]  = { ctx->primaryDevice, ctx->secondaryDevice };

  for (int i = 0; i < 2; i++) {
    CommonInputs* mapped = NULL;
    err = vkMapMemory(
      devices[i],
      memories[i],
      0, // offset
      sizeof(CommonInputs),
      0, // flags
      (void**) &mapped
    );
    if (err) goto cleanup;

    memcpy(&mapped->sha256_state[0], shaCtxInitial.state, sizeof(uint32_t) * 8);

    // Copy the skSeed into a big-endian encoded u32 array
    for (size_t i = 0; i < HASH_WORDS; i++) {
      size_t i4 = i * sizeof(uint32_t);
      mapped->sk_seed[i] = ((uint32_t) skSeed[i4] << 24) | ((uint32_t) skSeed[i4 + 1] << 16) |
                           ((uint32_t) skSeed[i4 + 2] << 8) | (uint32_t) skSeed[i4 + 3];
    }
    mapped->tree_address = treeAddress;
    mapped->signing_keypair_address = signingKeypairAddress;
    vkUnmapMemory(devices[i], memories[i]);
  }

  // Submit the XMSS precomputation shaders right away, because they take the most runtime.
  VkSubmitInfo submitInfo = {
    .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
    .commandBufferCount = 1,
    .pCommandBuffers = &ctx->primaryHypertreePresignCommandBuffer,
  };
  err = vkQueueSubmit(primaryQueue, 1, &submitInfo, primaryFence);
  if (err) goto cleanup;

  // Write the FORS indices to the FORS message buffer so it will be signed.
  VkDeviceMemory forsMessageMemory = (ctx->secondaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)
    ? ctx->secondaryForsMessageBufferDeviceLocalMemory
    : ctx->secondaryForsMessageBufferHostVisibleMemory;
  uint32_t* mappedForsMessage = NULL;
  err = vkMapMemory(
    ctx->secondaryDevice,
    forsMessageMemory,
    0, // offset
    FORS_MESSAGE_BUFFER_SIZE,
    0, // flags
    (void**) &mappedForsMessage
  );
  if (err) goto cleanup;
  memcpy(mappedForsMessage, forsIndices, FORS_MESSAGE_BUFFER_SIZE);
  vkUnmapMemory(ctx->secondaryDevice, forsMessageMemory);

  // Submit the FORS command buffer to the secondary device.
  submitInfo.pCommandBuffers = &ctx->secondaryForsCommandBuffer;
  err = vkQueueSubmit(secondaryQueue, 1, &submitInfo, secondaryFence);
  if (err) goto cleanup;

  // Wait for secondary (FORS) shaders to complete
  err = vkWaitForFences(ctx->secondaryDevice, 1, &secondaryFence, VK_TRUE, 100e9);
  if (err) goto cleanup;

  // Read the FORS roots output.
  uint8_t* mappedForsRoots = NULL;
  err = vkMapMemory(
    ctx->secondaryDevice,
    ctx->secondaryForsRootsBufferMemory,
    0, // offset
    FORS_ROOTS_BUFFER_SIZE,
    0, // flags
    (void**) &mappedForsRoots
  );
  if (err) goto cleanup;
  uint8_t forsRoots[FORS_ROOTS_BUFFER_SIZE];
  memcpy(forsRoots, mappedForsRoots, FORS_ROOTS_BUFFER_SIZE);
  vkUnmapMemory(ctx->secondaryDevice, ctx->secondaryForsRootsBufferMemory);

  uint32_t wotsMessage[WOTS_CHAIN_COUNT];
  slhvkHashForsRootsToWotsMessage(
    forsRoots,
    treeAddress,
    signingKeypairAddress,
    &shaCtxInitial,
    wotsMessage
  );

  // Copy the encoded FORS pubkey WOTS message to the primary device staging buffer.
  uint32_t* mappedWotsMessage = NULL;
  err = vkMapMemory(
    ctx->primaryDevice,
    ctx->primaryForsPubkeyStagingBufferMemory,
    0, // offset
    FORS_PUBKEY_STAGING_BUFFER_SIZE,
    0, // flags
    (void**) &mappedWotsMessage
  );
  if (err) goto cleanup;
  for (int i = 0; i < WOTS_CHAIN_COUNT; i++) {
    mappedWotsMessage[i] = wotsMessage[i];
  }
  vkUnmapMemory(ctx->primaryDevice, ctx->primaryForsPubkeyStagingBufferMemory);

  // Wait for the XMSS precomputation shaders to finish. These take up the majority of runtime.
  err = vkWaitForFences(ctx->primaryDevice, 1, &primaryFence, VK_TRUE, 100e9);
  if (err) goto cleanup;

  // Reset this fence so we can reuse it for the final submission.
  err = vkResetFences(ctx->primaryDevice, 1, &primaryFence);
  if (err) goto cleanup;

  // Submit and await the final WOTS signing shader.
  submitInfo.pCommandBuffers = &ctx->primaryHypertreeFinishCommandBuffer;
  err = vkQueueSubmit(primaryQueue, 1, &submitInfo, primaryFence);
  if (err) goto cleanup;
  err = vkWaitForFences(ctx->primaryDevice, 1, &primaryFence, VK_TRUE, 100e9);
  if (err) goto cleanup;

  // Copy the randomizer to the signature output
  memcpy(signatureOutput, randomizer, N);

  // Copy the FORS signature to the output pointer
  uint8_t forsSig[FORS_SIGNATURE_SIZE];
  VkDeviceMemory forsSigMemory = (ctx->secondaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)
    ? ctx->secondaryForsSignatureBufferDeviceLocalMemory
    : ctx->secondaryForsSignatureBufferHostVisibleMemory;
  uint8_t* mappedSignature = NULL;
  err = vkMapMemory(ctx->secondaryDevice, forsSigMemory, 0, FORS_SIGNATURE_SIZE, 0, (void**) &mappedSignature);
  if (err) goto cleanup;
  memcpy(&signatureOutput[N], mappedSignature, FORS_SIGNATURE_SIZE);
  memcpy(forsSig, mappedSignature, FORS_SIGNATURE_SIZE);
  vkUnmapMemory(ctx->secondaryDevice, forsSigMemory);

  // Copy the hypertree signature to the output pointer
  VkDeviceMemory hypertreeSigMemory = (ctx->primaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)
    ? ctx->primaryHypertreeSignatureBufferDeviceLocalMemory
    : ctx->primaryHypertreeSignatureBufferHostVisibleMemory;
  err = vkMapMemory(ctx->primaryDevice, hypertreeSigMemory, 0, HYPERTREE_SIGNATURE_SIZE, 0, (void**) &mappedSignature);
  if (err) goto cleanup;
  memcpy(&signatureOutput[N + FORS_SIGNATURE_SIZE], mappedSignature, HYPERTREE_SIGNATURE_SIZE);
  vkUnmapMemory(ctx->primaryDevice, hypertreeSigMemory);

cleanup:
  vkDestroyFence(ctx->primaryDevice, primaryFence, NULL);
  vkDestroyFence(ctx->secondaryDevice, secondaryFence, NULL);
  return err;
}
