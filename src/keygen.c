#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "keygen.h"
#include "context.h"
#include "slhvk.h"
#include "vkutil.h"
#include "sha256.h"

static uint32_t min(uint32_t x, uint32_t y) {
  return x < y ? x : y;
}

void slhvkCachedRootTreeFree(SlhvkCachedRootTree_T* cachedRootTree) {
  if (cachedRootTree != NULL) {
    vkDestroyBuffer(cachedRootTree->ctx->primaryDevice, cachedRootTree->buffer, NULL);
    vkFreeMemory(cachedRootTree->ctx->primaryDevice, cachedRootTree->memory, NULL);
    free(cachedRootTree);
  }
}

int slhvkCachedRootTreeInit(SlhvkContext ctx, SlhvkCachedRootTree_T** cachedRootTreePtr) {
  int err = 0;
  VkBuffer buffer = NULL;
  VkDeviceMemory memory = NULL;
  VkMemoryPropertyFlags memFlags = 0;

  VkBufferCreateInfo bufferCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
    .sharingMode = VK_SHARING_MODE_EXCLUSIVE, // buffers are exclusive to a single queue family at a time.
    .size = SLHVK_XMSS_CACHED_TREE_SIZE,
    .usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
             VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
             VK_BUFFER_USAGE_TRANSFER_DST_BIT,
  };
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &buffer);
  if (err) goto cleanup;

  err = slhvkAllocateBufferMemory(
    ctx->primaryDevice,
    ctx->primaryPhysicalDevice,
    buffer,
    VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
    &memFlags,
    &memory
  );
  if (err) goto cleanup;

  SlhvkCachedRootTree_T* cachedRootTree = malloc(sizeof(SlhvkCachedRootTree_T));
  if (cachedRootTree == NULL) {
    err = SLHVK_ERROR_MEMORY_TYPE_NOT_FOUND;
    goto cleanup;
  }
  cachedRootTree->ctx = ctx;
  cachedRootTree->buffer = buffer;
  cachedRootTree->memory = memory;
  cachedRootTree->memFlags = memFlags;
  *cachedRootTreePtr = cachedRootTree;
  return 0;

cleanup:
  vkDestroyBuffer(ctx->primaryDevice, buffer, NULL);
  vkFreeMemory(ctx->primaryDevice, memory, NULL);
  return err;
}

int slhvkKeygenBulk(
  SlhvkContext ctx,
  uint32_t keysCount,
  uint8_t const* const* skSeeds,
  uint8_t const* const* pkSeeds,
  uint8_t** pkRootsOut,
  SlhvkCachedRootTree* cachedRootTreesOut
) {
  int err = 0;
  VkBuffer keygenIOStagingBuffer = NULL;
  VkBuffer keygenSha256StateStagingBuffer = NULL;
  VkBuffer keygenIOBuffer = NULL;
  VkBuffer keygenSha256StateBuffer = NULL;
  VkBuffer keygenWotsChainBuffer = NULL;
  VkBuffer keygenXmssNodesBuffer = NULL;
  VkBuffer keygenXmssRootTreesBuffer = NULL;

  VkDeviceMemory keygenIOStagingBufferMemory = NULL;
  VkDeviceMemory keygenSha256StateStagingBufferMemory = NULL;
  VkDeviceMemory keygenIOBufferMemory = NULL;
  VkDeviceMemory keygenSha256StateBufferMemory = NULL;
  VkDeviceMemory keygenWotsChainBufferMemory = NULL;
  VkDeviceMemory keygenXmssNodesBufferMemory = NULL;
  VkDeviceMemory keygenXmssRootTreesBufferMemory = NULL;

  VkFence fence = NULL;
  VkEvent keygenDoneEvent = NULL;

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
  const size_t xmssNodesBufferSize = keysChunkCount * N * SLHVK_XMSS_LEAVES;

  /**************  Create keygen buffers  *******************/

  VkBufferCreateInfo bufferCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
    .sharingMode = VK_SHARING_MODE_EXCLUSIVE, // buffers are exclusive to a single queue family at a time.
  };

  bufferCreateInfo.size = keygenIOBufferSize;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
                           VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
                           VK_BUFFER_USAGE_TRANSFER_DST_BIT;
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

  bufferCreateInfo.size = xmssNodesBufferSize;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &keygenXmssNodesBuffer);
  if (err) goto cleanup;

  if (cachedRootTreesOut != NULL) {
    bufferCreateInfo.size = xmssNodesBufferSize;
    bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
                             VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
                             VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &keygenXmssRootTreesBuffer);
    if (err) goto cleanup;
  }

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

  // This buffer doesn't need to be host visible
  if (cachedRootTreesOut != NULL) {
    err = slhvkAllocateBufferMemory(
      ctx->primaryDevice,
      ctx->primaryPhysicalDevice,
      keygenXmssRootTreesBuffer,
      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
      NULL,
      &keygenXmssRootTreesBufferMemory
    );
    if (err) goto cleanup;
  }

  slhvkBindBuffersToDescriptorSet(
    ctx->primaryDevice,
    keygenBuffers,
    KEYGEN_PIPELINE_DESCRIPTOR_COUNT,
    ctx->keygenDescriptorSet
  );


  /********  allocate a VkEvent to synchronize command buffers  *********/

  VkEventCreateInfo eventCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_EVENT_CREATE_INFO,
    .flags = VK_EVENT_CREATE_DEVICE_ONLY_BIT,
  };
  err = vkCreateEvent(ctx->primaryDevice, &eventCreateInfo, NULL, &keygenDoneEvent);
  if (err) goto cleanup;


  /********  allocate and fill the keygen command buffer  *********/

  VkCommandBuffer keygenCommandBuffers[2] = {
    ctx->primaryKeygenCommandBuffer,
    ctx->primaryXmssRootTreeCopyCommandBuffer,
  };

  err = vkResetCommandBuffer(keygenCommandBuffers[0], 0);
  if (err) goto cleanup;

  VkCommandBufferBeginInfo cmdBufBeginInfo = {
    .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
  };
  err = vkBeginCommandBuffer(keygenCommandBuffers[0], &cmdBufBeginInfo);
  if (err) goto cleanup;

  // If we needed a separate host-visible staging buffer, let's copy that to the device.
  if (keygenIOMemory == keygenIOStagingBufferMemory) {
    VkBufferCopy regions = { .size = keygenIOBufferSize };
    vkCmdCopyBuffer(
      keygenCommandBuffers[0],
      keygenIOStagingBuffer, // src
      keygenIOBuffer,        // dest
      1, // region count
      &regions // regions
    );
  }

  if (shaStateInputMemory == keygenSha256StateStagingBufferMemory) {
    VkBufferCopy regions = { .size = sha256StateBufferSize };
    vkCmdCopyBuffer(
      keygenCommandBuffers[0],
      keygenSha256StateStagingBuffer, // src
      keygenSha256StateBuffer,        // dest
      1, // region count
      &regions // regions
    );
  }

  // All keygen shaders share the same descriptor set (TODO)
  vkCmdBindDescriptorSets(
    keygenCommandBuffers[0],
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
    keygenCommandBuffers[0],
    ctx->keygenPipelineLayout,
    VK_SHADER_STAGE_COMPUTE_BIT,
    0, //  offset
    sizeof(keysChunkCount),
    &keysChunkCount
  );

  // Bind and dispatch the wots tips shader.
  vkCmdBindPipeline(
    keygenCommandBuffers[0],
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->keygenWotsTipsPipeline
  );
  vkCmdDispatch(
    keygenCommandBuffers[0],
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
    keygenCommandBuffers[0],
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    0, // flags
    1, &memoryBarrier, // VkMemoryBarrier[]
    0, NULL,           // VkBufferMemoryBarrier[]
    0, NULL            // VkImageMemoryBarrier[]
  );

  // Bind and dispatch the XMSS leaves shader.
  vkCmdBindPipeline(
    keygenCommandBuffers[0],
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->keygenXmssLeavesPipeline
  );
  vkCmdDispatch(
    keygenCommandBuffers[0],
    // One thread per chain in each key's root tree
    slhvkNumWorkGroups(keysChunkCount * SLHVK_XMSS_LEAVES),
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  // If needed, copy the root tree leaf nodes back to the host so they can be cached.
  if (cachedRootTreesOut != NULL) {
    VkBufferCopy regions = { .size = xmssNodesBufferSize };
    vkCmdCopyBuffer(
      keygenCommandBuffers[0],
      keygenXmssNodesBuffer,     // src
      keygenXmssRootTreesBuffer, // dest
      1, // region count
      &regions // regions
    );
  }

  // Specify that the XMSS roots shader depends on the output of the XMSS leaves shader.
  vkCmdPipelineBarrier(
    keygenCommandBuffers[0],
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
    0, // flags
    1, &memoryBarrier, // VkMemoryBarrier[]
    0, NULL,           // VkBufferMemoryBarrier[]
    0, NULL            // VkImageMemoryBarrier[]
  );

  // Bind and dispatch the XMSS roots shader.
  vkCmdBindPipeline(
    keygenCommandBuffers[0],
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->keygenXmssRootsPipeline
  );
  vkCmdDispatch(
    keygenCommandBuffers[0],
    keysChunkCount, // One work group per XMSS tree root to generate.
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  // Copy the output pubkey roots back to the staging IO buffer if needed.
  if (keygenIOMemory == keygenIOStagingBufferMemory) {
    VkBufferCopy regions = { .size = keygenIOBufferSize };
    vkCmdCopyBuffer(
      keygenCommandBuffers[0],
      keygenIOBuffer,        // src
      keygenIOStagingBuffer, // dest
      1, // region count
      &regions // regions
    );
  }

  vkCmdSetEvent(keygenCommandBuffers[0], keygenDoneEvent, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT);

  // We don't need to overwrite the SK Seeds in keygenIOBuffer, because
  // they are overwritten by the output of the XMSS roots shader on the device
  // local buffer and (if applicable) copied over the original staging buffer inputs.

  err = vkEndCommandBuffer(keygenCommandBuffers[0]);
  if (err) goto cleanup;

  /*******  Fill the inputs and execute each chunk iteration  ******/

  VkFenceCreateInfo fenceCreateInfo = { .sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO };
  err = vkCreateFence(ctx->primaryDevice, &fenceCreateInfo, NULL, &fence);
  if (err) goto cleanup;

  VkQueue primaryQueue;
  vkGetDeviceQueue(ctx->primaryDevice, ctx->primaryDeviceQueueFamily, 0, &primaryQueue);

  // Loop over each chunk of the inputs
  for (uint32_t keysGenerated = 0; keysGenerated < keysCount; keysGenerated += keysChunkCount) {
    uint32_t thisChunkSize = min(keysChunkCount, keysCount - keysGenerated);

    // Write the skSeeds arrays to the input buffer.
    uint32_t* mapped;
    err = vkMapMemory(ctx->primaryDevice, keygenIOMemory, 0, keygenIOBufferSize, 0, (void**) &mapped);
    if (err) goto cleanup;
    for (uint32_t i = 0; i < thisChunkSize; i++) {
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
    for (uint32_t i = 0; i < thisChunkSize; i++) {
      memcpy(sha256State, SLHVK_SHA256_INITIAL_STATE, sizeof(sha256State));
      memcpy(block, pkSeeds[keysGenerated + i], N);
      slhvkSha256Compress(sha256State, block);

      uint32_t offset = i * 8;
      for (uint32_t j = 0; j < 8; j++) {
        mapped[offset + j] = sha256State[j];
      }
    }
    vkUnmapMemory(ctx->primaryDevice, shaStateInputMemory);

    uint32_t commandBuffersToSubmit = 1;

    // Instruct the device to cache the XMSS root trees in the caller's given buffers
    // once the keygen is complete (if applicable).
    if (cachedRootTreesOut != NULL) {
      commandBuffersToSubmit += 1;
      err = vkResetCommandBuffer(keygenCommandBuffers[1], 0);
      if (err) goto cleanup;
      err = vkBeginCommandBuffer(keygenCommandBuffers[1], &cmdBufBeginInfo);
      if (err) goto cleanup;

      // Ensure this command buffer waits for the previous command buffer to finish.
      vkCmdWaitEvents(
        keygenCommandBuffers[1],
        1,
        &keygenDoneEvent,
        VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
        VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
        0, NULL, 0, NULL, 0, NULL
      );
      vkCmdResetEvent(keygenCommandBuffers[1], keygenDoneEvent, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT);

      VkBufferCopy region = { .size = SLHVK_XMSS_CACHED_TREE_SIZE };
      for (uint32_t i = 0; i < thisChunkSize; i++) {
        region.srcOffset = i * SLHVK_XMSS_CACHED_TREE_SIZE;
        vkCmdCopyBuffer(
          keygenCommandBuffers[1],
          keygenXmssRootTreesBuffer, // src
          cachedRootTreesOut[keysGenerated + i]->buffer, // dest
          1,
          &region
        );
      }

      err = vkEndCommandBuffer(keygenCommandBuffers[1]);
      if (err) goto cleanup;
    }

    VkSubmitInfo submitInfo = {
      .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
      .commandBufferCount = commandBuffersToSubmit,
      .pCommandBuffers = keygenCommandBuffers,
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
    for (uint32_t i = 0; i < thisChunkSize; i++) {
      for (uint32_t j = 0; j < N; j++) {
        pkRootsOut[keysGenerated + i][j] = pkRootsMapped[i][j];
      }
    }
    vkUnmapMemory(ctx->primaryDevice, keygenIOMemory);
  }

cleanup:
  vkDestroyEvent(ctx->primaryDevice, keygenDoneEvent, NULL);
  vkDestroyFence(ctx->primaryDevice, fence, NULL);
  vkDestroyBuffer(ctx->primaryDevice, keygenIOStagingBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, keygenSha256StateStagingBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, keygenIOBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, keygenSha256StateBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, keygenWotsChainBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, keygenXmssNodesBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, keygenXmssRootTreesBuffer, NULL);
  vkFreeMemory(ctx->primaryDevice, keygenIOStagingBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, keygenSha256StateStagingBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, keygenIOBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, keygenSha256StateBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, keygenWotsChainBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, keygenXmssNodesBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, keygenXmssRootTreesBufferMemory, NULL);
  return err;
}

int slhvkKeygen(
  SlhvkContext ctx,
  uint8_t const skSeed[SLHVK_N],
  uint8_t const pkSeed[SLHVK_N],
  uint8_t* pkRoot,
  SlhvkCachedRootTree cachedRootTree
) {
  uint8_t const* skSeeds[1] = { skSeed };
  uint8_t const* pkSeeds[1] = { pkSeed };
  uint8_t* pkRoots[1] = { pkRoot };
  SlhvkCachedRootTree cachedRootTrees[1] = { cachedRootTree };
  return slhvkKeygenBulk(ctx, 1, skSeeds, pkSeeds, pkRoots, cachedRootTrees);
}
