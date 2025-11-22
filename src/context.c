#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <vulkan/vulkan.h>

#include "slhvk.h"
#include "sha256.h"
#include "hashing.h"
#include "vkutil.h"
#include "context.h"
#include "shaders/keygen_wots_tips.h"
#include "shaders/keygen_xmss_leaves.h"
#include "shaders/keygen_xmss_roots.h"
#include "shaders/signing_wots_tips_precompute.h"
#include "shaders/signing_xmss_leaves_precompute.h"
#include "shaders/signing_xmss_merkle_sign.h"
#include "shaders/signing_wots_sign.h"
#include "shaders/signing_fors_leaves_gen.h"
#include "shaders/signing_fors_merkle_sign.h"
#include "shaders/verify.h"

#define MAX_DESCRIPTOR_SETS_PER_DEVICE 10
#define MAX_DESCRIPTORS_PER_DEVICE     20

#define SPEC_CONSTANTS_COUNT 1

static bool isEnvFlagEnabled(const char* envVarName) {
  char* flagValue = getenv(envVarName);
  return flagValue != NULL && (strcmp(flagValue, "1") == 0 || strcmp(flagValue, "true") == 0);
}

void slhvkContextFree(SlhvkContext_T* ctx) {
  if (ctx != NULL) {
    /********** Free device resources **********/
    if (ctx->primaryDevice != NULL) {
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

      // Primary signing resources
      vkDestroyShaderModule(ctx->primaryDevice, ctx->wotsTipsPrecomputeShader, NULL);
      vkDestroyShaderModule(ctx->primaryDevice, ctx->xmssLeavesPrecomputeShader, NULL);
      vkDestroyShaderModule(ctx->primaryDevice, ctx->xmssMerkleSignShader, NULL);
      vkDestroyShaderModule(ctx->primaryDevice, ctx->wotsSignShader, NULL);
      vkDestroyPipeline(ctx->primaryDevice, ctx->wotsTipsPrecomputePipeline, NULL);
      vkDestroyPipeline(ctx->primaryDevice, ctx->xmssLeavesPrecomputePipeline, NULL);
      vkDestroyPipeline(ctx->primaryDevice, ctx->xmssMerkleSignPipeline, NULL);
      vkDestroyPipeline(ctx->primaryDevice, ctx->wotsSignPipeline, NULL);
      vkDestroyPipelineLayout(ctx->primaryDevice, ctx->primarySigningPipelineLayout, NULL);
      vkDestroyDescriptorSetLayout(ctx->primaryDevice, ctx->primarySigningDescriptorSetLayout, NULL);
      vkDestroyEvent(ctx->primaryDevice, ctx->primaryXmssRootTreeCopyDoneEvent, NULL);

      // Secondary signing resources
      vkDestroyShaderModule(ctx->secondaryDevice, ctx->forsLeavesGenShader, NULL);
      vkDestroyShaderModule(ctx->secondaryDevice, ctx->forsMerkleSignShader, NULL);
      vkDestroyPipeline(ctx->secondaryDevice, ctx->forsLeavesGenPipeline, NULL);
      vkDestroyPipeline(ctx->secondaryDevice, ctx->forsMerkleSignPipeline, NULL);
      vkDestroyPipelineLayout(ctx->secondaryDevice, ctx->secondarySigningPipelineLayout, NULL);
      vkDestroyDescriptorSetLayout(ctx->secondaryDevice, ctx->secondarySigningDescriptorSetLayout, NULL);

      // Keygen resources
      vkDestroyShaderModule(ctx->primaryDevice, ctx->keygenWotsTipsShader, NULL);
      vkDestroyShaderModule(ctx->primaryDevice, ctx->keygenXmssLeavesShader, NULL);
      vkDestroyShaderModule(ctx->primaryDevice, ctx->keygenXmssRootsShader, NULL);
      vkDestroyPipeline(ctx->primaryDevice, ctx->keygenWotsTipsPipeline, NULL);
      vkDestroyPipeline(ctx->primaryDevice, ctx->keygenXmssLeavesPipeline, NULL);
      vkDestroyPipeline(ctx->primaryDevice, ctx->keygenXmssRootsPipeline, NULL);
      vkDestroyPipelineLayout(ctx->primaryDevice, ctx->keygenPipelineLayout, NULL);
      vkDestroyDescriptorSetLayout(ctx->primaryDevice, ctx->keygenDescriptorSetLayout, NULL);

      // Verify resources
      vkDestroyShaderModule(ctx->primaryDevice, ctx->verifyShader, NULL);
      vkDestroyPipeline(ctx->primaryDevice, ctx->verifyPipeline, NULL);
      vkDestroyPipelineLayout(ctx->primaryDevice, ctx->verifyPipelineLayout, NULL);
      vkDestroyDescriptorSetLayout(ctx->primaryDevice, ctx->verifyDescriptorSetLayout, NULL);

      // Primary command buffers
      VkCommandBuffer primaryCommandBuffers[] = {
        ctx->primaryHypertreePresignCommandBuffer,
        ctx->primaryHypertreeFinishCommandBuffer,
        ctx->primaryXmssRootTreeCopyCommandBuffer,
        ctx->primaryKeygenCommandBuffer,
        ctx->primaryVerifyCommandBuffer,
      };
      vkFreeCommandBuffers(ctx->primaryDevice, ctx->primaryCommandPool, 5, primaryCommandBuffers);

      // Secondary command buffers
      vkFreeCommandBuffers(ctx->secondaryDevice, ctx->secondaryCommandPool, 1, &ctx->secondaryForsCommandBuffer);

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
    }

    vkDestroyInstance(ctx->instance, NULL);
    free(ctx);
  }
}

int slhvkContextInit(SlhvkContext_T** ctxPtr) {
  VkPhysicalDevice* physicalDevices = NULL;
  SlhvkContext_T* ctx = calloc(1, sizeof(SlhvkContext_T));
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
  if (isEnvFlagEnabled("SLHVK_ENABLE_VALIDATION_LAYERS")) {
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
  }

  // enable macOS support via MoltenVK
  #ifdef __APPLE__
    const char* extensions[] = {"VK_KHR_portability_enumeration"};
    instanceCreateInfo.flags = VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR,
    instanceCreateInfo.enabledExtensionCount = sizeof(extensions) / sizeof(char*),
    instanceCreateInfo.ppEnabledExtensionNames = extensions;
  #endif

  err = vkCreateInstance(&instanceCreateInfo, NULL, &ctx->instance);
  if (err) goto cleanup;


  /**************  Find primary and secondary physical devices  *****************/

  uint32_t physicalDevicesCount = 0;
  err = vkEnumeratePhysicalDevices(ctx->instance, &physicalDevicesCount, NULL);
  if (err) goto cleanup;
  else if (physicalDevicesCount == 0) {
    err = SLHVK_ERROR_NO_COMPUTE_DEVICE;
    goto cleanup;
  }

  physicalDevices = (VkPhysicalDevice*) malloc(physicalDevicesCount * sizeof(VkPhysicalDevice));
  err = vkEnumeratePhysicalDevices(ctx->instance, &physicalDevicesCount, physicalDevices);
  if (err) return err;
  else if (physicalDevicesCount == 0) {
    err = SLHVK_ERROR_NO_COMPUTE_DEVICE;
    goto cleanup;
  }

  bool forceCpu = isEnvFlagEnabled("SLHVK_FORCE_CPU");
  bool forceGpu = isEnvFlagEnabled("SLHVK_FORCE_GPU");

  // Select a primary device (and secondary device too if one is available).
  for (uint32_t i = 0; i < physicalDevicesCount; i++) {
    int computeQueueFamily = slhvkFindDeviceComputeQueueFamily(physicalDevices[i]);
    if (computeQueueFamily < 0) continue; // doesn't support compute shaders

    VkPhysicalDeviceProperties deviceProps;
    vkGetPhysicalDeviceProperties(physicalDevices[i], &deviceProps);

    if (forceCpu && deviceProps.deviceType != VK_PHYSICAL_DEVICE_TYPE_CPU)
      continue;
    if (forceGpu && deviceProps.deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU)
      continue;

    // First, use any two devices. Then, replace the primary and secondary devices if
    // we find any superior available devices.
    if (ctx->primaryPhysicalDevice == NULL) {
      ctx->primaryPhysicalDevice = physicalDevices[i];
      ctx->primaryDeviceProperties = deviceProps;
      ctx->primaryDeviceQueueFamily = computeQueueFamily;
    } else if (ctx->secondaryPhysicalDevice == NULL) {
      ctx->secondaryPhysicalDevice = physicalDevices[i];
      ctx->secondaryDeviceProperties = deviceProps;
      ctx->secondaryDeviceQueueFamily = computeQueueFamily;
    } else if (deviceProps.limits.maxComputeSharedMemorySize > ctx->primaryDeviceProperties.limits.maxComputeSharedMemorySize) {
      ctx->primaryPhysicalDevice = physicalDevices[i];
      ctx->primaryDeviceProperties = deviceProps;
      ctx->primaryDeviceQueueFamily = computeQueueFamily;
    } else if (deviceProps.limits.maxComputeSharedMemorySize > ctx->secondaryDeviceProperties.limits.maxComputeSharedMemorySize) {
      ctx->secondaryPhysicalDevice = physicalDevices[i];
      ctx->secondaryDeviceProperties = deviceProps;
      ctx->secondaryDeviceQueueFamily = computeQueueFamily;
    }
  }

  free(physicalDevices);
  physicalDevices = NULL;

  if (ctx->primaryPhysicalDevice == NULL) {
    err = SLHVK_ERROR_NO_COMPUTE_DEVICE;
    goto cleanup;
  }

  // Only one device available. Use it as primary and secondary.
  if (ctx->secondaryPhysicalDevice == NULL) {
    ctx->secondaryPhysicalDevice = ctx->primaryPhysicalDevice;
    ctx->secondaryDeviceProperties = ctx->primaryDeviceProperties;
    ctx->secondaryDeviceQueueFamily = ctx->primaryDeviceQueueFamily;
  } else if (
    ctx->secondaryDeviceProperties.limits.maxComputeSharedMemorySize > ctx->primaryDeviceProperties.limits.maxComputeSharedMemorySize
  ) {
    // If the secondary device is better than the primary, swap them so the primary is always more powerful.
    VkPhysicalDevice           tmpDevice      = ctx->secondaryPhysicalDevice;
    VkPhysicalDeviceProperties tmpProps       = ctx->secondaryDeviceProperties;
    uint32_t                   tmpQueueFamily = ctx->secondaryDeviceQueueFamily;

    ctx->secondaryPhysicalDevice = ctx->primaryPhysicalDevice;
    ctx->secondaryDeviceProperties = ctx->primaryDeviceProperties;
    ctx->secondaryDeviceQueueFamily = ctx->primaryDeviceQueueFamily;
    ctx->primaryPhysicalDevice = tmpDevice;
    ctx->primaryDeviceProperties = tmpProps;
    ctx->primaryDeviceQueueFamily = tmpQueueFamily;
  }


  /*****************  Create logical device(s)  **********************/

  float priority = 1.0;
  VkDeviceQueueCreateInfo queueCreateInfo = {
      .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
      .queueFamilyIndex = ctx->primaryDeviceQueueFamily,
      .queueCount = 1,
      .pQueuePriorities = &priority,
  };
  VkDeviceCreateInfo deviceCreateInfo = {
      .sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
      .pQueueCreateInfos = &queueCreateInfo,
      .queueCreateInfoCount = 1,
  };
  err = vkCreateDevice(ctx->primaryPhysicalDevice, &deviceCreateInfo, NULL, &ctx->primaryDevice);
  if (err) goto cleanup;

  if (ctx->secondaryPhysicalDevice == ctx->primaryPhysicalDevice) {
    ctx->secondaryDevice = ctx->primaryDevice;
  } else {
    queueCreateInfo.queueFamilyIndex = ctx->secondaryDeviceQueueFamily;
    err = vkCreateDevice(ctx->secondaryPhysicalDevice, &deviceCreateInfo, NULL, &ctx->secondaryDevice);
    if (err) goto cleanup;
  }


  /**************  Create command pool(s)  *****************/

  VkCommandPoolCreateInfo commandPoolCreateInfo = {
      .sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
      .flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
      .queueFamilyIndex = ctx->primaryDeviceQueueFamily,
  };
  err = vkCreateCommandPool(ctx->primaryDevice, &commandPoolCreateInfo, NULL, &ctx->primaryCommandPool);
  if (err) goto cleanup;

  if (ctx->secondaryDevice == ctx->primaryDevice) {
    ctx->secondaryCommandPool = ctx->primaryCommandPool;
  } else {
    commandPoolCreateInfo.queueFamilyIndex = ctx->secondaryDeviceQueueFamily;
    err = vkCreateCommandPool(ctx->secondaryDevice, &commandPoolCreateInfo, NULL, &ctx->secondaryCommandPool);
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
  err = vkCreateDescriptorPool(ctx->primaryDevice, &descriptorPoolCreateInfo, NULL, &ctx->primaryDescriptorPool);
  if (err) goto cleanup;

  if (ctx->secondaryDevice == ctx->primaryDevice) {
    ctx->secondaryDescriptorPool = ctx->primaryDescriptorPool;
  } else {
    err = vkCreateDescriptorPool(ctx->secondaryDevice, &descriptorPoolCreateInfo, NULL, &ctx->secondaryDescriptorPool);
    if (err) goto cleanup;
  }


  /****************  Initialize buffers  ******************/

  VkBufferCreateInfo bufferCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
    .sharingMode = VK_SHARING_MODE_EXCLUSIVE, // buffers are exclusive to a single queue family at a time.
  };

  bufferCreateInfo.size = sizeof(CommonSigningInputs);
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &ctx->primaryInputsBufferDeviceLocal);
  if (err) goto cleanup;

  bufferCreateInfo.size = sizeof(CommonSigningInputs);
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
                           VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
                           VK_BUFFER_USAGE_TRANSFER_DST_BIT; // Need DST because we want to use vkCmdFillBuffer
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &ctx->primaryInputsBufferHostVisible);
  if (err) goto cleanup;

  bufferCreateInfo.size = WOTS_CHAIN_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &ctx->primaryWotsChainBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = XMSS_NODES_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &ctx->primaryXmssNodesBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = XMSS_MESSAGES_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &ctx->primaryXmssMessagesBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = FORS_PUBKEY_STAGING_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &ctx->primaryForsPubkeyStagingBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = SLHVK_HYPERTREE_SIGNATURE_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &ctx->primaryHypertreeSignatureBufferDeviceLocal);
  if (err) goto cleanup;

  bufferCreateInfo.size = SLHVK_HYPERTREE_SIGNATURE_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &ctx->primaryHypertreeSignatureBufferHostVisible);
  if (err) goto cleanup;

  /**** Secondary device buffers ****/

  bufferCreateInfo.size = sizeof(CommonSigningInputs);
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx->secondaryDevice, &bufferCreateInfo, NULL, &ctx->secondaryInputsBufferDeviceLocal);
  if (err) goto cleanup;

  bufferCreateInfo.size = sizeof(CommonSigningInputs);
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
                           VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
                           VK_BUFFER_USAGE_TRANSFER_DST_BIT; // Need DST because we want to use vkCmdFillBuffer
  err = vkCreateBuffer(ctx->secondaryDevice, &bufferCreateInfo, NULL, &ctx->secondaryInputsBufferHostVisible);
  if (err) goto cleanup;

  bufferCreateInfo.size = FORS_MESSAGE_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx->secondaryDevice, &bufferCreateInfo, NULL, &ctx->secondaryForsMessageBufferDeviceLocal);
  if (err) goto cleanup;

  bufferCreateInfo.size = FORS_MESSAGE_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx->secondaryDevice, &bufferCreateInfo, NULL, &ctx->secondaryForsMessageBufferHostVisible);
  if (err) goto cleanup;

  bufferCreateInfo.size = FORS_NODES_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx->secondaryDevice, &bufferCreateInfo, NULL, &ctx->secondaryForsNodesBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = SLHVK_FORS_SIGNATURE_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx->secondaryDevice, &bufferCreateInfo, NULL, &ctx->secondaryForsSignatureBufferDeviceLocal);
  if (err) goto cleanup;

  bufferCreateInfo.size = SLHVK_FORS_SIGNATURE_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx->secondaryDevice, &bufferCreateInfo, NULL, &ctx->secondaryForsSignatureBufferHostVisible);
  if (err) goto cleanup;

  bufferCreateInfo.size = FORS_ROOTS_BUFFER_SIZE;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx->secondaryDevice, &bufferCreateInfo, NULL, &ctx->secondaryForsRootsBuffer);
  if (err) goto cleanup;


  /*******************  Allocate primary device local memory  **********************/

  #define PRIMARY_DEVICE_LOCAL_BUFFER_COUNT 5
  VkBuffer primaryDeviceLocalBuffers[PRIMARY_DEVICE_LOCAL_BUFFER_COUNT] = {
    ctx->primaryInputsBufferDeviceLocal,
    ctx->primaryWotsChainBuffer,
    ctx->primaryXmssNodesBuffer,
    ctx->primaryXmssMessagesBuffer,
    ctx->primaryHypertreeSignatureBufferDeviceLocal,
  };
  VkDeviceMemory* primaryDeviceLocalMemories[PRIMARY_DEVICE_LOCAL_BUFFER_COUNT] = {
    &ctx->primaryInputsBufferDeviceLocalMemory,
    &ctx->primaryWotsChainBufferMemory,
    &ctx->primaryXmssNodesBufferMemory,
    &ctx->primaryXmssMessagesBufferMemory,
    &ctx->primaryHypertreeSignatureBufferDeviceLocalMemory,
  };

  for (uint32_t i = 0; i < PRIMARY_DEVICE_LOCAL_BUFFER_COUNT; i++) {
    err = slhvkAllocateBufferMemory(
      ctx->primaryDevice,
      ctx->primaryPhysicalDevice,
      primaryDeviceLocalBuffers[i],
      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
      &ctx->primaryDeviceLocalMemoryFlags, // TODO: assumes buffers end up with the same memory type
      primaryDeviceLocalMemories[i]
    );
    if (err) goto cleanup;
  }


  /*******************  Allocate secondary device local memory  **********************/

  #define SECONDARY_DEVICE_LOCAL_BUFFER_COUNT 4
  VkBuffer secondaryDeviceLocalBuffers[SECONDARY_DEVICE_LOCAL_BUFFER_COUNT] = {
    ctx->secondaryInputsBufferDeviceLocal,
    ctx->secondaryForsMessageBufferDeviceLocal,
    ctx->secondaryForsNodesBuffer,
    ctx->secondaryForsSignatureBufferDeviceLocal,
  };
  VkDeviceMemory* secondaryDeviceLocalMemories[SECONDARY_DEVICE_LOCAL_BUFFER_COUNT] = {
    &ctx->secondaryInputsBufferDeviceLocalMemory,
    &ctx->secondaryForsMessageBufferDeviceLocalMemory,
    &ctx->secondaryForsNodesBufferMemory,
    &ctx->secondaryForsSignatureBufferDeviceLocalMemory,
  };

  for (uint32_t i = 0; i < SECONDARY_DEVICE_LOCAL_BUFFER_COUNT; i++) {
    err = slhvkAllocateBufferMemory(
      ctx->secondaryDevice,
      ctx->secondaryPhysicalDevice,
      secondaryDeviceLocalBuffers[i],
      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
      &ctx->secondaryDeviceLocalMemoryFlags, // TODO: assumes buffers end up with the same memory type
      secondaryDeviceLocalMemories[i]
    );
    if (err) goto cleanup;
  }


  /*******************  Allocate primary host visible memory  **********************/

  // Only allocate if device local memory isn't already host-visible.
  if (!(ctx->primaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)) {
    err = slhvkAllocateBufferMemory(
      ctx->primaryDevice,
      ctx->primaryPhysicalDevice,
      ctx->primaryInputsBufferHostVisible,
      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
      &ctx->primaryDeviceHostVisibleMemoryFlags,
      &ctx->primaryInputsBufferHostVisibleMemory
    );
    if (err) goto cleanup;

    err = slhvkAllocateBufferMemory(
      ctx->primaryDevice,
      ctx->primaryPhysicalDevice,
      ctx->primaryHypertreeSignatureBufferHostVisible,
      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
      &ctx->primaryDeviceHostVisibleMemoryFlags,
      &ctx->primaryHypertreeSignatureBufferHostVisibleMemory
    );
    if (err) goto cleanup;
  }

  err = slhvkAllocateBufferMemory(
    ctx->primaryDevice,
    ctx->primaryPhysicalDevice,
    ctx->primaryForsPubkeyStagingBuffer,
    VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
    &ctx->primaryDeviceHostVisibleMemoryFlags,
    &ctx->primaryForsPubkeyStagingBufferMemory
  );
  if (err) goto cleanup;


  /*******************  Allocate secondary host visible memory  **********************/

  // Only allocate if device local memory isn't already host-visible.
  if (!(ctx->secondaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)) {
    err = slhvkAllocateBufferMemory(
      ctx->secondaryDevice,
      ctx->secondaryPhysicalDevice,
      ctx->secondaryInputsBufferHostVisible,
      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
      &ctx->secondaryDeviceHostVisibleMemoryFlags,
      &ctx->secondaryInputsBufferHostVisibleMemory
    );
    if (err) goto cleanup;

    err = slhvkAllocateBufferMemory(
      ctx->secondaryDevice,
      ctx->secondaryPhysicalDevice,
      ctx->secondaryForsMessageBufferHostVisible,
      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
      &ctx->secondaryDeviceHostVisibleMemoryFlags,
      &ctx->secondaryForsMessageBufferHostVisibleMemory
    );
    if (err) goto cleanup;

    err = slhvkAllocateBufferMemory(
      ctx->secondaryDevice,
      ctx->secondaryPhysicalDevice,
      ctx->secondaryForsSignatureBufferHostVisible,
      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
      &ctx->secondaryDeviceHostVisibleMemoryFlags,
      &ctx->secondaryForsSignatureBufferHostVisibleMemory
    );
    if (err) goto cleanup;
  }

  err = slhvkAllocateBufferMemory(
    ctx->secondaryDevice,
    ctx->secondaryPhysicalDevice,
    ctx->secondaryForsRootsBuffer,
    VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
    &ctx->secondaryDeviceHostVisibleMemoryFlags,
    &ctx->secondaryForsRootsBufferMemory
  );
  if (err) goto cleanup;


  /*******************  Define descriptor set layouts  **********************/

  err = slhvkSetupDescriptorSetLayout(
    ctx->primaryDevice,
    PRIMARY_SIGNING_PIPELINE_DESCRIPTOR_COUNT,
    &ctx->primarySigningDescriptorSetLayout
  );
  if (err) goto cleanup;

  err = slhvkSetupDescriptorSetLayout(
    ctx->secondaryDevice,
    SECONDARY_SIGNING_PIPELINE_DESCRIPTOR_COUNT,
    &ctx->secondarySigningDescriptorSetLayout
  );
  if (err) goto cleanup;

  err = slhvkSetupDescriptorSetLayout(
    ctx->primaryDevice,
    KEYGEN_PIPELINE_DESCRIPTOR_COUNT,
    &ctx->keygenDescriptorSetLayout
  );
  if (err) goto cleanup;

  err = slhvkSetupDescriptorSetLayout(
    ctx->primaryDevice,
    VERIFY_PIPELINE_DESCRIPTOR_COUNT,
    &ctx->verifyDescriptorSetLayout
  );
  if (err) goto cleanup;


  /*******************  Define pipeline layouts  **********************/

  VkPipelineLayoutCreateInfo pipelineLayoutCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
    .setLayoutCount = 1,
  };

  pipelineLayoutCreateInfo.pSetLayouts = &ctx->primarySigningDescriptorSetLayout,
  err = vkCreatePipelineLayout(
    ctx->primaryDevice,
    &pipelineLayoutCreateInfo,
    NULL,
    &ctx->primarySigningPipelineLayout
  );
  if (err) goto cleanup;

  pipelineLayoutCreateInfo.pSetLayouts = &ctx->secondarySigningDescriptorSetLayout,
  err = vkCreatePipelineLayout(
    ctx->secondaryDevice,
    &pipelineLayoutCreateInfo,
    NULL,
    &ctx->secondarySigningPipelineLayout
  );
  if (err) goto cleanup;

  VkPushConstantRange pushConstantRange = {
    .stageFlags = VK_SHADER_STAGE_COMPUTE_BIT,
    .size = sizeof(uint32_t),
  };
  pipelineLayoutCreateInfo.pPushConstantRanges = &pushConstantRange;
  pipelineLayoutCreateInfo.pushConstantRangeCount = 1;
  pipelineLayoutCreateInfo.pSetLayouts = &ctx->keygenDescriptorSetLayout,
  err = vkCreatePipelineLayout(
    ctx->primaryDevice,
    &pipelineLayoutCreateInfo,
    NULL,
    &ctx->keygenPipelineLayout
  );
  if (err) goto cleanup;

  pipelineLayoutCreateInfo.pSetLayouts = &ctx->verifyDescriptorSetLayout,
  err = vkCreatePipelineLayout(
    ctx->primaryDevice,
    &pipelineLayoutCreateInfo,
    NULL,
    &ctx->verifyPipelineLayout
  );
  if (err) goto cleanup;


  /*******************  Allocate primary descriptor sets  **********************/

  VkDescriptorSetAllocateInfo descriptorSetAllocateInfo = {
    .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
    .descriptorPool = ctx->primaryDescriptorPool, // pool to allocate from.
    .descriptorSetCount = 1,                     // allocate a single descriptor set per pipeline.
  };

  descriptorSetAllocateInfo.pSetLayouts = &ctx->primarySigningDescriptorSetLayout;
  err = vkAllocateDescriptorSets(ctx->primaryDevice, &descriptorSetAllocateInfo, &ctx->primarySigningDescriptorSet);
  if (err) goto cleanup;

  descriptorSetAllocateInfo.pSetLayouts = &ctx->keygenDescriptorSetLayout;
  err = vkAllocateDescriptorSets(ctx->primaryDevice, &descriptorSetAllocateInfo, &ctx->keygenDescriptorSet);
  if (err) goto cleanup;

  descriptorSetAllocateInfo.pSetLayouts = &ctx->verifyDescriptorSetLayout;
  err = vkAllocateDescriptorSets(ctx->primaryDevice, &descriptorSetAllocateInfo, &ctx->verifyDescriptorSet);
  if (err) goto cleanup;


  /*******************  Allocate secondary descriptor sets  **********************/

  descriptorSetAllocateInfo.descriptorPool = ctx->secondaryDescriptorPool;
  descriptorSetAllocateInfo.pSetLayouts = &ctx->secondarySigningDescriptorSetLayout;
  err = vkAllocateDescriptorSets(ctx->secondaryDevice, &descriptorSetAllocateInfo, &ctx->secondarySigningDescriptorSet);
  if (err) goto cleanup;

  /*******************  Bind device buffers to descriptor sets  **********************/

  VkBuffer primarySigningBuffers[PRIMARY_SIGNING_PIPELINE_DESCRIPTOR_COUNT] = {
    ctx->primaryInputsBufferDeviceLocal,
    ctx->primaryWotsChainBuffer,
    ctx->primaryXmssNodesBuffer,
    ctx->primaryHypertreeSignatureBufferDeviceLocal,
    ctx->primaryXmssMessagesBuffer,
  };
  slhvkBindBuffersToDescriptorSet(
    ctx->primaryDevice,
    primarySigningBuffers,
    PRIMARY_SIGNING_PIPELINE_DESCRIPTOR_COUNT,
    ctx->primarySigningDescriptorSet
  );

  VkBuffer secondarySigningBuffers[SECONDARY_SIGNING_PIPELINE_DESCRIPTOR_COUNT] = {
    ctx->secondaryInputsBufferDeviceLocal,
    ctx->secondaryForsMessageBufferDeviceLocal,
    ctx->secondaryForsNodesBuffer,
    ctx->secondaryForsSignatureBufferDeviceLocal,
  };
  slhvkBindBuffersToDescriptorSet(
    ctx->secondaryDevice,
    secondarySigningBuffers,
    SECONDARY_SIGNING_PIPELINE_DESCRIPTOR_COUNT,
    ctx->secondarySigningDescriptorSet
  );


  /*******************  Build shader modules  **********************/

  VkShaderModuleCreateInfo shaderCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
  };

  shaderCreateInfo.pCode = (uint32_t*) signing_wots_tips_precompute_spv,
  shaderCreateInfo.codeSize = signing_wots_tips_precompute_spv_len,
  err = vkCreateShaderModule(ctx->primaryDevice, &shaderCreateInfo, NULL, &ctx->wotsTipsPrecomputeShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) signing_xmss_leaves_precompute_spv,
  shaderCreateInfo.codeSize = signing_xmss_leaves_precompute_spv_len,
  err = vkCreateShaderModule(ctx->primaryDevice, &shaderCreateInfo, NULL, &ctx->xmssLeavesPrecomputeShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) signing_xmss_merkle_sign_spv,
  shaderCreateInfo.codeSize = signing_xmss_merkle_sign_spv_len,
  err = vkCreateShaderModule(ctx->primaryDevice, &shaderCreateInfo, NULL, &ctx->xmssMerkleSignShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) signing_wots_sign_spv,
  shaderCreateInfo.codeSize = signing_wots_sign_spv_len,
  err = vkCreateShaderModule(ctx->primaryDevice, &shaderCreateInfo, NULL, &ctx->wotsSignShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) keygen_wots_tips_spv,
  shaderCreateInfo.codeSize = keygen_wots_tips_spv_len,
  err = vkCreateShaderModule(ctx->primaryDevice, &shaderCreateInfo, NULL, &ctx->keygenWotsTipsShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) keygen_xmss_leaves_spv,
  shaderCreateInfo.codeSize = keygen_xmss_leaves_spv_len,
  err = vkCreateShaderModule(ctx->primaryDevice, &shaderCreateInfo, NULL, &ctx->keygenXmssLeavesShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) keygen_xmss_roots_spv,
  shaderCreateInfo.codeSize = keygen_xmss_roots_spv_len,
  err = vkCreateShaderModule(ctx->primaryDevice, &shaderCreateInfo, NULL, &ctx->keygenXmssRootsShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) verify_spv;
  shaderCreateInfo.codeSize = verify_spv_len;
  err = vkCreateShaderModule(ctx->primaryDevice, &shaderCreateInfo, NULL, &ctx->verifyShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) signing_fors_leaves_gen_spv,
  shaderCreateInfo.codeSize = signing_fors_leaves_gen_spv_len,
  err = vkCreateShaderModule(ctx->secondaryDevice, &shaderCreateInfo, NULL, &ctx->forsLeavesGenShader);
  if (err) goto cleanup;

  shaderCreateInfo.pCode = (uint32_t*) signing_fors_merkle_sign_spv,
  shaderCreateInfo.codeSize = signing_fors_merkle_sign_spv_len,
  err = vkCreateShaderModule(ctx->secondaryDevice, &shaderCreateInfo, NULL, &ctx->forsMerkleSignShader);
  if (err) goto cleanup;


  /**********  Define specialization constants  **********/

  const uint32_t specializationConstants[SPEC_CONSTANTS_COUNT] = {
    SLHVK_DEFAULT_WORK_GROUP_SIZE,
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

  pipelineCreateInfo.stage.module = ctx->wotsTipsPrecomputeShader;
  pipelineCreateInfo.layout       = ctx->primarySigningPipelineLayout;
  err = vkCreateComputePipelines(
    ctx->primaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx->wotsTipsPrecomputePipeline
  );
  if (err) goto cleanup;

  pipelineCreateInfo.stage.module = ctx->xmssLeavesPrecomputeShader;
  pipelineCreateInfo.layout       = ctx->primarySigningPipelineLayout;
  err = vkCreateComputePipelines(
    ctx->primaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx->xmssLeavesPrecomputePipeline
  );
  if (err) goto cleanup;

  pipelineCreateInfo.stage.module = ctx->xmssMerkleSignShader;
  pipelineCreateInfo.layout       = ctx->primarySigningPipelineLayout;
  err = vkCreateComputePipelines(
    ctx->primaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx->xmssMerkleSignPipeline
  );
  if (err) goto cleanup;

  pipelineCreateInfo.stage.module = ctx->wotsSignShader;
  pipelineCreateInfo.layout       = ctx->primarySigningPipelineLayout;
  err = vkCreateComputePipelines(
    ctx->primaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx->wotsSignPipeline
  );
  if (err) goto cleanup;

  pipelineCreateInfo.stage.module = ctx->keygenWotsTipsShader;
  pipelineCreateInfo.layout       = ctx->keygenPipelineLayout;
  err = vkCreateComputePipelines(
    ctx->primaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx->keygenWotsTipsPipeline
  );
  if (err) {
    goto cleanup;
  }

  pipelineCreateInfo.stage.module = ctx->keygenXmssLeavesShader;
  pipelineCreateInfo.layout       = ctx->keygenPipelineLayout;
  err = vkCreateComputePipelines(
    ctx->primaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx->keygenXmssLeavesPipeline
  );
  if (err) goto cleanup;

  pipelineCreateInfo.stage.module = ctx->keygenXmssRootsShader;
  pipelineCreateInfo.layout       = ctx->keygenPipelineLayout;
  err = vkCreateComputePipelines(
    ctx->primaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx->keygenXmssRootsPipeline
  );
  if (err) goto cleanup;

  pipelineCreateInfo.stage.module = ctx->verifyShader;
  pipelineCreateInfo.layout       = ctx->verifyPipelineLayout;
  err = vkCreateComputePipelines(
    ctx->primaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx->verifyPipeline
  );
  if (err) goto cleanup;

  pipelineCreateInfo.stage.module = ctx->forsLeavesGenShader;
  pipelineCreateInfo.layout       = ctx->secondarySigningPipelineLayout;
  err = vkCreateComputePipelines(
    ctx->secondaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx->forsLeavesGenPipeline
  );
  if (err) goto cleanup;

  pipelineCreateInfo.stage.module = ctx->forsMerkleSignShader;
  pipelineCreateInfo.layout       = ctx->secondarySigningPipelineLayout;
  err = vkCreateComputePipelines(
    ctx->secondaryDevice,
    VK_NULL_HANDLE, // pipeline cache, TODO
    1,
    &pipelineCreateInfo,
    NULL,
    &ctx->forsMerkleSignPipeline
  );
  if (err) goto cleanup;


  /**************  Create an event to synchronize command buffers  ****************/

  VkEventCreateInfo eventCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_EVENT_CREATE_INFO,
    .flags = VK_EVENT_CREATE_DEVICE_ONLY_BIT,
  };
  err = vkCreateEvent(ctx->primaryDevice, &eventCreateInfo, NULL, &ctx->primaryXmssRootTreeCopyDoneEvent);
  if (err) goto cleanup;


  /*****************  Create primary device command buffers ******************/

  #define PRIMARY_COMMAND_BUFFER_COUNT 5
  VkCommandBufferAllocateInfo cmdBufAllocInfo = {
    .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
    .commandPool = ctx->primaryCommandPool,
    .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
    .commandBufferCount = PRIMARY_COMMAND_BUFFER_COUNT,
  };
  VkCommandBuffer primaryCmdBufs[PRIMARY_COMMAND_BUFFER_COUNT];
  err = vkAllocateCommandBuffers(ctx->primaryDevice, &cmdBufAllocInfo, primaryCmdBufs);
  if (err) goto cleanup;

  ctx->primaryHypertreePresignCommandBuffer = primaryCmdBufs[0];
  ctx->primaryHypertreeFinishCommandBuffer  = primaryCmdBufs[1];
  ctx->primaryXmssRootTreeCopyCommandBuffer = primaryCmdBufs[2];
  ctx->primaryKeygenCommandBuffer           = primaryCmdBufs[3];
  ctx->primaryVerifyCommandBuffer           = primaryCmdBufs[4];


  /*****************  Create secondary device command buffers ******************/

  cmdBufAllocInfo.commandPool = ctx->secondaryCommandPool;
  cmdBufAllocInfo.commandBufferCount = 1;
  err = vkAllocateCommandBuffers(ctx->secondaryDevice, &cmdBufAllocInfo, &ctx->secondaryForsCommandBuffer);
  if (err) goto cleanup;


  /**************  Fill the presigning primary device command buffer  ***************/

  VkCommandBufferBeginInfo cmdBufBeginInfo = {
    .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
  };
  err = vkBeginCommandBuffer(ctx->primaryHypertreePresignCommandBuffer, &cmdBufBeginInfo);
  if (err) goto cleanup;

  // Copy from a host-visible buffer if the device-local buffer isn't also host-visible.
  if ((ctx->primaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) == 0) {
    VkBufferCopy regions = { .size = sizeof(CommonSigningInputs) };
    vkCmdCopyBuffer(
      ctx->primaryHypertreePresignCommandBuffer,
      ctx->primaryInputsBufferHostVisible, // src
      ctx->primaryInputsBufferDeviceLocal, // dest
      1, // region count
      &regions // regions
    );

    // Overwrite the SK seed in host-visible memory
    vkCmdFillBuffer(
      ctx->primaryHypertreePresignCommandBuffer,
      ctx->primaryInputsBufferHostVisible,
      0, // offset
      VK_WHOLE_SIZE,
      0 // data
    );
  }

  vkCmdBindDescriptorSets(
    ctx->primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->primarySigningPipelineLayout,
    0, // set number of first descriptor_set to be bound
    1, // number of descriptor sets
    &ctx->primarySigningDescriptorSet,
    0,  // offset count
    NULL // offsets array
  );

  // Bind and dispatch the WOTS tips precompute shader.
  vkCmdBindPipeline(
    ctx->primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->wotsTipsPrecomputePipeline
  );
  vkCmdDispatch(
    ctx->primaryHypertreePresignCommandBuffer,
    slhvkNumWorkGroups(SLHVK_HYPERTREE_LAYERS * SLHVK_XMSS_LEAVES * SLHVK_WOTS_CHAIN_COUNT),
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
    ctx->primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    0, // flags
    1, &xmssLeavesPrecomputeMemoryBarrier, // VkMemoryBarrier[]
    0, NULL,                               // VkBufferMemoryBarrier[]
    0, NULL                                // VkImageMemoryBarrier[]
  );

  // Bind and dispatch the XMSS leaves precompute shader.
  vkCmdBindPipeline(
    ctx->primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->xmssLeavesPrecomputePipeline
  );
  vkCmdDispatch(
    ctx->primaryHypertreePresignCommandBuffer,
    slhvkNumWorkGroups(SLHVK_HYPERTREE_LAYERS * SLHVK_XMSS_LEAVES),
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  // Wait to ensure the cached XMSS tree has been copied into the XMSS nodes
  // buffer (if available).
  vkCmdWaitEvents(
    ctx->primaryHypertreePresignCommandBuffer,
    1,
    &ctx->primaryXmssRootTreeCopyDoneEvent,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    0, NULL, 0, NULL, 0, NULL
  );
  vkCmdResetEvent(
    ctx->primaryHypertreePresignCommandBuffer,
    ctx->primaryXmssRootTreeCopyDoneEvent,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT
  );

  // Specify that the XMSS sign shader depends on the XMSS nodes
  // buffer output from the XMSS leaves precompute shader.
  VkMemoryBarrier xmssMerkleSignMemoryBarrier = {
    .sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER,
    .srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT,
    .dstAccessMask = VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_SHADER_WRITE_BIT,
  };
  vkCmdPipelineBarrier(
    ctx->primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    0, // flags
    1, &xmssMerkleSignMemoryBarrier, // VkMemoryBarrier[]
    0, NULL,                         // VkBufferMemoryBarrier[]
    0, NULL                          // VkImageMemoryBarrier[]
  );

  // Bind and dispatch the XMSS merkle sign precompute shader.
  vkCmdBindPipeline(
    ctx->primaryHypertreePresignCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->xmssMerkleSignPipeline
  );
  vkCmdDispatch(
    ctx->primaryHypertreePresignCommandBuffer,
    SLHVK_HYPERTREE_LAYERS, // One work group per XMSS tree
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  err = vkEndCommandBuffer(ctx->primaryHypertreePresignCommandBuffer);
  if (err) goto cleanup;


  /**************  Fill the secondary FORS-signing command buffer *****************/

  err = vkBeginCommandBuffer(ctx->secondaryForsCommandBuffer, &cmdBufBeginInfo);
  if (err) goto cleanup;

  // Copy from host-visible buffers if the device-local buffer isn't also host-visible.
  if ((ctx->secondaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) == 0) {
    VkBufferCopy regions = { .size = sizeof(CommonSigningInputs) };
    vkCmdCopyBuffer(
      ctx->secondaryForsCommandBuffer,
      ctx->secondaryInputsBufferHostVisible, // src
      ctx->secondaryInputsBufferDeviceLocal, // dest
      1, // region count
      &regions // regions
    );

    // Overwrite the SK seed in host-visible memory
    vkCmdFillBuffer(
      ctx->secondaryForsCommandBuffer,
      ctx->secondaryInputsBufferHostVisible,
      0, // offset
      VK_WHOLE_SIZE,
      0 // data
    );

    regions.size = FORS_MESSAGE_BUFFER_SIZE;
    vkCmdCopyBuffer(
      ctx->secondaryForsCommandBuffer,
      ctx->secondaryForsMessageBufferHostVisible, // src
      ctx->secondaryForsMessageBufferDeviceLocal, // dest
      1, // region count
      &regions // regions
    );
  }

  vkCmdBindDescriptorSets(
    ctx->secondaryForsCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->secondarySigningPipelineLayout,
    0, // set number of first descriptor_set to be bound
    1, // number of descriptor sets
    &ctx->secondarySigningDescriptorSet,
    0,  // offset count
    NULL // offsets array
  );

  // Bind and dispatch the FORS leaves gen shader.
  vkCmdBindPipeline(
    ctx->secondaryForsCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->forsLeavesGenPipeline
  );
  vkCmdDispatch(
    ctx->secondaryForsCommandBuffer,
    slhvkNumWorkGroups(SLHVK_FORS_TREE_COUNT * SLHVK_FORS_LEAVES_COUNT), // One thread per FORS leaf node
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
    ctx->secondaryForsCommandBuffer,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    0, // flags
    1, &forsMerkleSignMemoryBarrier, // VkMemoryBarrier[]
    0, NULL,                         // VkBufferMemoryBarrier[]
    0, NULL                          // VkImageMemoryBarrier[]
  );

  // Bind and dispatch the FORS merkle sign shader.
  vkCmdBindPipeline(
    ctx->secondaryForsCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->forsMerkleSignPipeline
  );
  vkCmdDispatch(
    ctx->secondaryForsCommandBuffer,
    SLHVK_FORS_TREE_COUNT, // One work group per FORS tree
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  // Copy to host-visible buffer if the device-local buffer isn't also host-visible.
  if ((ctx->secondaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) == 0) {
    VkBufferCopy regions = { .size = SLHVK_FORS_SIGNATURE_SIZE };
    vkCmdCopyBuffer(
      ctx->secondaryForsCommandBuffer,
      ctx->secondaryForsSignatureBufferDeviceLocal, // src
      ctx->secondaryForsSignatureBufferHostVisible, // dest
      1, // region count
      &regions // regions
    );
  }

  // Copy each of the computed FORS tree root hashes to a host-visible buffer.
  VkBufferCopy forsRootsCopyRegions[SLHVK_FORS_TREE_COUNT];
  for (uint32_t i = 0; i < SLHVK_FORS_TREE_COUNT; i++) {
    forsRootsCopyRegions[i] = (VkBufferCopy) {
      .srcOffset = i * SLHVK_FORS_LEAVES_COUNT * N,
      .dstOffset = i * N,
      .size = N,
    };
  }
  vkCmdCopyBuffer(
    ctx->secondaryForsCommandBuffer,
    ctx->secondaryForsNodesBuffer, // src
    ctx->secondaryForsRootsBuffer, // dest
    SLHVK_FORS_TREE_COUNT, // region count
    forsRootsCopyRegions
  );

  // Overwrite the SK seed in device-local memory
  vkCmdFillBuffer(
    ctx->secondaryForsCommandBuffer,
    ctx->secondaryInputsBufferDeviceLocal,
    0, // offset
    VK_WHOLE_SIZE,
    0 // data
  );

  err = vkEndCommandBuffer(ctx->secondaryForsCommandBuffer);
  if (err) goto cleanup;


  /*************  Fill the primary device finish-signing command buffer  **************/

  err = vkBeginCommandBuffer(ctx->primaryHypertreeFinishCommandBuffer, &cmdBufBeginInfo);
  if (err) goto cleanup;

  // Copy the FORS pubkey to the XMSS messages buffer
  VkBufferCopy regions = {
    .size = FORS_PUBKEY_STAGING_BUFFER_SIZE,
    .srcOffset = 0,
    .dstOffset = 0,
  };
  vkCmdCopyBuffer(
    ctx->primaryHypertreeFinishCommandBuffer,
    ctx->primaryForsPubkeyStagingBuffer, // src
    ctx->primaryXmssMessagesBuffer, // dest
    1, // region count
    &regions
  );

  vkCmdBindDescriptorSets(
    ctx->primaryHypertreeFinishCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->primarySigningPipelineLayout,
    0, // set number of first descriptor_set to be bound
    1, // number of descriptor sets
    &ctx->primarySigningDescriptorSet,
    0,  // offset count
    NULL // offsets array
  );

  // Bind and dispatch the final WOTS signing shader.
  vkCmdBindPipeline(
    ctx->primaryHypertreeFinishCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->wotsSignPipeline
  );
  vkCmdDispatch(
    ctx->primaryHypertreeFinishCommandBuffer,
    slhvkNumWorkGroups(SLHVK_HYPERTREE_LAYERS * SLHVK_WOTS_CHAIN_COUNT), // One thread per signing chain
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  // Copy to a host-visible buffer if the device-local buffer isn't also host-visible.
  if ((ctx->primaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) == 0) {
    VkBufferCopy regions = { .size = SLHVK_HYPERTREE_SIGNATURE_SIZE };
    vkCmdCopyBuffer(
      ctx->primaryHypertreeFinishCommandBuffer,
      ctx->primaryHypertreeSignatureBufferDeviceLocal, // src
      ctx->primaryHypertreeSignatureBufferHostVisible, // dest
      1, // region count
      &regions // regions
    );
  }

  // Overwrite the SK seed in device-local memory
  vkCmdFillBuffer(
    ctx->primaryHypertreeFinishCommandBuffer,
    ctx->primaryInputsBufferDeviceLocal,
    0, // offset
    VK_WHOLE_SIZE,
    0 // data
  );

  err = vkEndCommandBuffer(ctx->primaryHypertreeFinishCommandBuffer);
  if (err) goto cleanup;

  *ctxPtr = ctx;
  return 0;

cleanup:
  free(physicalDevices);
  slhvkContextFree(ctx);
  return err;
}
