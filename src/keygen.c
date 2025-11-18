#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "context.h"
#include "slhvk.h"
#include "vkutil.h"
#include "sha256.h"

int slhvkKeygen(
  SlhvkContext ctx,
  uint32_t keysCount,
  uint8_t* const* skSeeds,
  uint8_t* const* pkSeeds,
  uint8_t** pkRootsOut
) {
  int err = 0;
  VkBuffer keygenIOStagingBuffer = NULL;
  VkBuffer keygenSha256StateStagingBuffer = NULL;
  VkBuffer keygenIOBuffer = NULL;
  VkBuffer keygenSha256StateBuffer = NULL;
  VkBuffer keygenWotsChainBuffer = NULL;
  VkBuffer keygenXmssNodesBuffer = NULL;

  VkDeviceMemory keygenIOStagingBufferMemory = NULL;
  VkDeviceMemory keygenSha256StateStagingBufferMemory = NULL;
  VkDeviceMemory keygenIOBufferMemory = NULL;
  VkDeviceMemory keygenSha256StateBufferMemory = NULL;
  VkDeviceMemory keygenWotsChainBufferMemory = NULL;
  VkDeviceMemory keygenXmssNodesBufferMemory = NULL;

  VkFence fence = NULL;

  uint32_t keysChunkCount = keysCount;

  // Scale the chunks size down until we meet device limits.
  VkPhysicalDeviceLimits* limits = &ctx->primaryDeviceProperties.limits;
  while (
    slhvkNumWorkGroups(keysChunkCount * SLHVK_XMSS_LEAVES * SLHVK_WOTS_CHAIN_COUNT) > limits->maxComputeWorkGroupCount[0] ||
    N * keysChunkCount * SLHVK_WOTS_CHAIN_COUNT * SLHVK_XMSS_LEAVES > limits->maxStorageBufferRange
  ) {
    keysChunkCount >>= 1;
  }

  const size_t keygenIOBufferSize = keysChunkCount * N;
  const size_t sha256StateBufferSize = keysChunkCount * 8 * sizeof(uint32_t);

  /**************  Create keygen buffers  *******************/

  VkBufferCreateInfo bufferCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
    .sharingMode = VK_SHARING_MODE_EXCLUSIVE, // buffers are exclusive to a single queue family at a time.
  };

  bufferCreateInfo.size = keygenIOBufferSize;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &keygenIOBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = sha256StateBufferSize;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &keygenSha256StateBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = keysChunkCount * N * SLHVK_WOTS_CHAIN_COUNT * SLHVK_XMSS_LEAVES;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &keygenWotsChainBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = keysChunkCount * N * SLHVK_XMSS_LEAVES;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &keygenXmssNodesBuffer);
  if (err) goto cleanup;


  /***************  Allocate keygen buffer memory backing  ********************/

  VkBuffer keygenBuffers[KEYGEN_PIPELINE_DESCRIPTOR_COUNT] = {
    keygenIOBuffer,
    keygenSha256StateBuffer,
    keygenWotsChainBuffer,
    keygenXmssNodesBuffer,
  };
  VkDeviceMemory* keygenMemories[KEYGEN_PIPELINE_DESCRIPTOR_COUNT] = {
    &keygenIOBufferMemory,
    &keygenSha256StateBufferMemory,
    &keygenWotsChainBufferMemory,
    &keygenXmssNodesBufferMemory,
  };

  VkMemoryPropertyFlags deviceLocalMemFlags;
  for (int i = 0; i < KEYGEN_PIPELINE_DESCRIPTOR_COUNT; i++) {
    err = slhvkAllocateBufferMemory(
      ctx->primaryDevice,
      ctx->primaryPhysicalDevice,
      keygenBuffers[i],
      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
      &deviceLocalMemFlags,
      keygenMemories[i]
    );
    if (err) goto cleanup;
  }

  // If needed, allocate host-visible staging buffers to send the inputs and receive the outputs.
  VkDeviceMemory shaStateInputMemory = keygenSha256StateBufferMemory;
  VkDeviceMemory keygenIOMemory = keygenIOBufferMemory;

  if (!(deviceLocalMemFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)) {
    bufferCreateInfo.size = keysChunkCount * N;
    bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
                             VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
                             VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &keygenIOStagingBuffer);
    if (err) goto cleanup;

    bufferCreateInfo.size = keysChunkCount * 8 * sizeof(uint32_t);
    bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &keygenSha256StateStagingBuffer);
    if (err) goto cleanup;


    err = slhvkAllocateBufferMemory(
      ctx->primaryDevice,
      ctx->primaryPhysicalDevice,
      keygenIOStagingBuffer,
      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
      NULL,
      &keygenIOStagingBufferMemory
    );
    if (err) goto cleanup;

    err = slhvkAllocateBufferMemory(
      ctx->primaryDevice,
      ctx->primaryPhysicalDevice,
      keygenSha256StateStagingBuffer,
      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
      NULL,
      &keygenSha256StateStagingBufferMemory
    );
    if (err) goto cleanup;

    keygenIOMemory = keygenIOStagingBufferMemory;
    shaStateInputMemory = keygenSha256StateStagingBufferMemory;
  }

  slhvkBindBuffersToDescriptorSet(
    ctx->primaryDevice,
    keygenBuffers,
    KEYGEN_PIPELINE_DESCRIPTOR_COUNT,
    ctx->keygenDescriptorSet
  );

  /********  allocate and fill a keygen command buffer  *********/

  VkCommandBufferAllocateInfo cmdBufAllocInfo = {
    .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
    .commandPool = ctx->primaryCommandPool,
    .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
    .commandBufferCount = 1,
  };
  VkCommandBuffer primaryKeygenCommandBuffer;
  err = vkAllocateCommandBuffers(ctx->primaryDevice, &cmdBufAllocInfo, &primaryKeygenCommandBuffer);
  if (err) goto cleanup;


  VkCommandBufferBeginInfo cmdBufBeginInfo = {
    .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
  };
  err = vkBeginCommandBuffer(primaryKeygenCommandBuffer, &cmdBufBeginInfo);
  if (err) goto cleanup;

  // If we needed a separate host-visible staging buffer, let's copy that to the device.
  if (keygenIOMemory == keygenIOStagingBufferMemory) {
    VkBufferCopy regions = { .size = keygenIOBufferSize };
    vkCmdCopyBuffer(
      primaryKeygenCommandBuffer,
      keygenIOStagingBuffer, // src
      keygenIOBuffer,        // dest
      1, // region count
      &regions // regions
    );
  }

  if (shaStateInputMemory == keygenSha256StateStagingBufferMemory) {
    VkBufferCopy regions = { .size = sha256StateBufferSize };
    vkCmdCopyBuffer(
      primaryKeygenCommandBuffer,
      keygenSha256StateStagingBuffer, // src
      keygenSha256StateBuffer,        // dest
      1, // region count
      &regions // regions
    );
  }

  // All keygen shaders share the same descriptor set (TODO)
  vkCmdBindDescriptorSets(
    primaryKeygenCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->keygenPipelineLayout,
    0, // set number of first descriptor_set to be bound
    1, // number of descriptor sets
    &ctx->keygenDescriptorSet,
    0,  // offset count
    NULL // offsets array
  );

  // Provide the key count as a push constant.
  vkCmdPushConstants(
    primaryKeygenCommandBuffer,
    ctx->keygenPipelineLayout,
    VK_SHADER_STAGE_COMPUTE_BIT,
    0, //  offset
    sizeof(keysChunkCount),
    &keysChunkCount
  );

  // Bind and dispatch the wots tips shader.
  vkCmdBindPipeline(
    primaryKeygenCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->keygenWotsTipsPipeline
  );
  vkCmdDispatch(
    primaryKeygenCommandBuffer,
    // One thread per chain in each key's root tree
    slhvkNumWorkGroups(keysChunkCount * SLHVK_XMSS_LEAVES * SLHVK_WOTS_CHAIN_COUNT),
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  // Specify that the XMSS leaves shader depends on the WOTS chain buffer
  // output from the WOTS tip shader.
  VkMemoryBarrier memoryBarrier = {
    .sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER,
    .srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT,
    .dstAccessMask = VK_ACCESS_SHADER_READ_BIT,
  };
  vkCmdPipelineBarrier(
    primaryKeygenCommandBuffer,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    0, // flags
    1, &memoryBarrier, // VkMemoryBarrier[]
    0, NULL,           // VkBufferMemoryBarrier[]
    0, NULL            // VkImageMemoryBarrier[]
  );

  // Bind and dispatch the XMSS leaves shader.
  vkCmdBindPipeline(
    primaryKeygenCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->keygenXmssLeavesPipeline
  );
  vkCmdDispatch(
    primaryKeygenCommandBuffer,
    // One thread per chain in each key's root tree
    slhvkNumWorkGroups(keysChunkCount * SLHVK_XMSS_LEAVES),
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  // Specify that the XMSS roots shader depends on the output of the XMSS leaves shader.
  vkCmdPipelineBarrier(
    primaryKeygenCommandBuffer,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    0, // flags
    1, &memoryBarrier, // VkMemoryBarrier[]
    0, NULL,           // VkBufferMemoryBarrier[]
    0, NULL            // VkImageMemoryBarrier[]
  );

  // Bind and dispatch the XMSS roots shader.
  vkCmdBindPipeline(
    primaryKeygenCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->keygenXmssRootsPipeline
  );
  vkCmdDispatch(
    primaryKeygenCommandBuffer,
    keysChunkCount, // One work group per XMSS tree root to generate.
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  // Copy the output pubkey roots back to the staging IO buffer if needed.
  if (keygenIOMemory == keygenIOStagingBufferMemory) {
    VkBufferCopy regions = { .size = keygenIOBufferSize };
    vkCmdCopyBuffer(
      primaryKeygenCommandBuffer,
      keygenIOBuffer,        // src
      keygenIOStagingBuffer, // dest
      1, // region count
      &regions // regions
    );
  }

  // We don't need to overwrite the SK Seeds in keygenIOBuffer, because
  // they are overwritten by the output of the XMSS roots shader on the device
  // local buffer and (if applicable) copied over the original staging buffer inputs.

  err = vkEndCommandBuffer(primaryKeygenCommandBuffer);
  if (err) goto cleanup;


  /*******  Fill the inputs and execute each chunk iteration  ******/

  VkFenceCreateInfo fenceCreateInfo = { .sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO };
  err = vkCreateFence(ctx->primaryDevice, &fenceCreateInfo, NULL, &fence);
  if (err) goto cleanup;

  VkQueue primaryQueue;
  vkGetDeviceQueue(ctx->primaryDevice, ctx->primaryDeviceQueueFamily, 0, &primaryQueue);

  // Loop over each chunk of the inputs
  for (uint32_t keysGenerated = 0; keysGenerated < keysCount; keysGenerated += keysChunkCount) {

    // Write the skSeeds arrays to the input buffer.
    uint32_t* mapped;
    err = vkMapMemory(ctx->primaryDevice, keygenIOMemory, 0, keygenIOBufferSize, 0, (void**) &mapped);
    if (err) goto cleanup;
    for (uint32_t i = 0; i < keysChunkCount && keysGenerated + i < keysCount; i++) {
      uint32_t offset = i * SLHVK_HASH_WORDS;
      for (uint32_t j = 0; j < SLHVK_HASH_WORDS; j++) {
        uint32_t j4 = j * sizeof(uint32_t);
        mapped[offset + j] = ((uint32_t) skSeeds[keysGenerated + i][j4 + 0] << 24) |
                             ((uint32_t) skSeeds[keysGenerated + i][j4 + 1] << 16) |
                             ((uint32_t) skSeeds[keysGenerated + i][j4 + 2] << 8) |
                             ((uint32_t) skSeeds[keysGenerated + i][j4 + 3] << 0);
      }
    }
    vkUnmapMemory(ctx->primaryDevice, keygenIOMemory);

    // Generate and write the sha256 midstates to the input buffer.
    err = vkMapMemory(ctx->primaryDevice, shaStateInputMemory, 0, sha256StateBufferSize, 0, (void**) &mapped);
    if (err) goto cleanup;
    uint8_t block[64] = {0};
    uint32_t sha256State[8];
    for (uint32_t i = 0; i < keysChunkCount && keysGenerated + i < keysCount; i++) {
      memcpy(sha256State, SLHVK_SHA256_INITIAL_STATE, sizeof(sha256State));
      memcpy(block, pkSeeds[keysGenerated + i], N);
      slhvkSha256Compress(sha256State, block);

      uint32_t offset = i * 8;
      for (uint32_t j = 0; j < 8; j++) {
        mapped[offset + j] = sha256State[j];
      }
    }
    vkUnmapMemory(ctx->primaryDevice, shaStateInputMemory);


    VkSubmitInfo submitInfo = {
      .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
      .commandBufferCount = 1,
      .pCommandBuffers = &primaryKeygenCommandBuffer,
    };

    err = vkQueueSubmit(primaryQueue, 1, &submitInfo, fence);
    if (err) goto cleanup;
    err = vkWaitForFences(ctx->primaryDevice, 1, &fence, VK_TRUE, 100e9);
    if (err) goto cleanup;
    err = vkResetFences(ctx->primaryDevice, 1, &fence);
    if (err) goto cleanup;

    // Read the pkRoots from the IO buffer.
    uint8_t (*pkRootsMapped)[N];
    err = vkMapMemory(ctx->primaryDevice, keygenIOMemory, 0, keygenIOBufferSize, 0, (void**) &pkRootsMapped);
    if (err) goto cleanup;
    for (uint32_t i = 0; i < keysChunkCount && keysGenerated + i < keysCount; i++) {
      for (uint32_t j = 0; j < N; j++) {
        pkRootsOut[keysGenerated + i][j] = pkRootsMapped[i][j];
      }
    }
    vkUnmapMemory(ctx->primaryDevice, keygenIOMemory);
  }

cleanup:
  vkDestroyFence(ctx->primaryDevice, fence, NULL);
  vkDestroyBuffer(ctx->primaryDevice, keygenIOStagingBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, keygenSha256StateStagingBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, keygenIOBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, keygenSha256StateBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, keygenWotsChainBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, keygenXmssNodesBuffer, NULL);
  vkFreeMemory(ctx->primaryDevice, keygenIOStagingBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, keygenSha256StateStagingBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, keygenIOBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, keygenSha256StateBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, keygenWotsChainBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, keygenXmssNodesBufferMemory, NULL);
  return err;
}
