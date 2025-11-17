#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vulkan/vulkan.h>

#include "slhvk.h"
#include "context.h"
#include "hashing.h"
#include "vkutil.h"

static size_t min(size_t x, size_t y) {
  if (x < y) return x;
  return y;
}

#define SIGNATURE_WORDS_WITHOUT_RANDOMIZER ((SLHVK_FORS_SIGNATURE_SIZE + SLHVK_HYPERTREE_SIGNATURE_SIZE) / sizeof(uint32_t))

typedef struct SlhvkSignatureVerifyRequest {
  uint32_t pkSeed[SLHVK_HASH_WORDS];
  uint32_t signingKeypairAddress;
  uint32_t treeAddress[2]; // dont use uint64_t, to avoid alignment issues
  uint32_t forsIndices[SLHVK_FORS_TREE_COUNT];
  uint32_t signature[SIGNATURE_WORDS_WITHOUT_RANDOMIZER];
} SlhvkSignatureVerifyRequest;

int slhvkVerifyPure(
  SlhvkContext ctx,
  uint32_t signaturesLen,
  uint8_t* const* contextStrings,
  uint8_t const* contextStringSizes,
  uint8_t* const* pkSeeds,
  uint8_t* const* pkRoots,
  uint8_t* const* signatures,
  uint8_t* const* messages,
  size_t const* messageSizes,
  int* verifyResultsOut
) {
  int err = 0;
  VkBuffer signaturesBuffer = NULL;
  VkBuffer signaturesStagingBuffer = NULL;
  VkBuffer verifyResultsBuffer = NULL;
  VkBuffer verifyResultsStagingBuffer = NULL;

  VkDeviceMemory signaturesBufferMemory = NULL;
  VkDeviceMemory signaturesStagingBufferMemory = NULL;
  VkDeviceMemory verifyResultsBufferMemory = NULL;
  VkDeviceMemory verifyResultsStagingBufferMemory = NULL;

  VkFence fence = NULL;

  uint32_t signaturesChunkCount = signaturesLen;

  // Scale the chunks size down until we meet device limits.
  VkPhysicalDeviceLimits* limits = &ctx->primaryDeviceProperties.limits;
  while (
    slhvkNumWorkGroups(signaturesChunkCount) > limits->maxComputeWorkGroupCount[0] ||
    signaturesChunkCount * sizeof(SlhvkSignatureVerifyRequest) > limits->maxStorageBufferRange
  ) {
    signaturesChunkCount >>= 1;
  }

  const size_t signaturesBufferSize = signaturesChunkCount * sizeof(SlhvkSignatureVerifyRequest);
  const size_t verifyResultsBufferSize = signaturesChunkCount * N;


  /**********  Create verification buffers  *************/

  VkBufferCreateInfo bufferCreateInfo = {
    .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
    .sharingMode = VK_SHARING_MODE_EXCLUSIVE, // buffers are exclusive to a single queue family at a time.
  };

  bufferCreateInfo.size = signaturesBufferSize;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &signaturesBuffer);
  if (err) goto cleanup;

  bufferCreateInfo.size = signaturesBufferSize;
  bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
  err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &verifyResultsBuffer);
  if (err) goto cleanup;


  /**************  Allocate verification buffer memory  ***************/

  VkMemoryPropertyFlags signaturesBufMemFlags;
  VkMemoryPropertyFlags verifyResultsBufMemFlags;

  err = slhvkAllocateBufferMemory(
    ctx->primaryDevice,
    ctx->primaryPhysicalDevice,
    signaturesBuffer,
    VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
    &signaturesBufMemFlags,
    &signaturesBufferMemory
  );
  if (err) goto cleanup;

  err = slhvkAllocateBufferMemory(
    ctx->primaryDevice,
    ctx->primaryPhysicalDevice,
    verifyResultsBuffer,
    VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
    &verifyResultsBufMemFlags,
    &verifyResultsBufferMemory
  );
  if (err) goto cleanup;

  VkDeviceMemory signaturesInputMemory = signaturesBufferMemory;
  VkDeviceMemory verifyResultsOutputMemory = verifyResultsBufferMemory;

  // Allocate host-visible buffer and memory if needed
  if (!(signaturesBufMemFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)) {
    bufferCreateInfo.size = signaturesBufferSize;
    bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &signaturesStagingBuffer);
    if (err) goto cleanup;

    err = slhvkAllocateBufferMemory(
      ctx->primaryDevice,
      ctx->primaryPhysicalDevice,
      signaturesStagingBuffer,
      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
      NULL,
      &signaturesStagingBufferMemory
    );
    if (err) goto cleanup;
    signaturesInputMemory = signaturesStagingBufferMemory;
  }
  if (!(verifyResultsBufMemFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)) {
    bufferCreateInfo.size = verifyResultsBufferSize;
    bufferCreateInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    err = vkCreateBuffer(ctx->primaryDevice, &bufferCreateInfo, NULL, &verifyResultsStagingBuffer);
    if (err) goto cleanup;

    err = slhvkAllocateBufferMemory(
      ctx->primaryDevice,
      ctx->primaryPhysicalDevice,
      verifyResultsStagingBuffer,
      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
      NULL,
      &verifyResultsStagingBufferMemory
    );
    if (err) goto cleanup;
    verifyResultsOutputMemory = verifyResultsStagingBufferMemory;
  }

  VkBuffer verifyBuffers[VERIFY_PIPELINE_DESCRIPTOR_COUNT] = { signaturesBuffer, verifyResultsBuffer };
  slhvkBindBuffersToDescriptorSet(
    ctx->primaryDevice,
    verifyBuffers,
    VERIFY_PIPELINE_DESCRIPTOR_COUNT,
    ctx->verifyDescriptorSet
  );


  /********  allocate and fill a verification command buffer  *********/

  VkCommandBufferAllocateInfo cmdBufAllocInfo = {
    .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
    .commandPool = ctx->primaryCommandPool,
    .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
    .commandBufferCount = 1,
  };
  VkCommandBuffer verifyCommandBuffer;
  err = vkAllocateCommandBuffers(ctx->primaryDevice, &cmdBufAllocInfo, &verifyCommandBuffer);
  if (err) goto cleanup;


  VkCommandBufferBeginInfo cmdBufBeginInfo = {
    .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
  };
  err = vkBeginCommandBuffer(verifyCommandBuffer, &cmdBufBeginInfo);
  if (err) goto cleanup;

  // If we needed a separate host-visible staging buffer, let's copy that to the device.
  if (signaturesInputMemory == signaturesStagingBufferMemory) {
    VkBufferCopy regions = { .size = signaturesBufferSize };
    vkCmdCopyBuffer(
      verifyCommandBuffer,
      signaturesStagingBuffer, // src
      signaturesBuffer,        // dest
      1, // region count
      &regions // regions
    );
  }

  vkCmdBindDescriptorSets(
    verifyCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->verifyPipelineLayout,
    0, // set number of first descriptor_set to be bound
    1, // number of descriptor sets
    &ctx->verifyDescriptorSet,
    0,  // offset count
    NULL // offsets array
  );

  // Provide the signatures count as a push constant.
  vkCmdPushConstants(
    verifyCommandBuffer,
    ctx->verifyPipelineLayout,
    VK_SHADER_STAGE_COMPUTE_BIT,
    0, //  offset
    sizeof(signaturesChunkCount),
    &signaturesChunkCount
  );

  // Bind and dispatch the verification shader.
  vkCmdBindPipeline(
    verifyCommandBuffer,
    VK_PIPELINE_BIND_POINT_COMPUTE,
    ctx->verifyPipeline
  );
  vkCmdDispatch(
    verifyCommandBuffer,
    slhvkNumWorkGroups(signaturesChunkCount), // One thread per signature
    1,  // Y dimension workgroups
    1   // Z dimension workgroups
  );

  // Copy the output pubkey roots back to the staging IO buffer if needed.
  if (verifyResultsOutputMemory == verifyResultsStagingBufferMemory) {
    VkBufferCopy regions = { .size = verifyResultsBufferSize };
    vkCmdCopyBuffer(
      verifyCommandBuffer,
      verifyResultsBuffer,        // src
      verifyResultsStagingBuffer, // dest
      1, // region count
      &regions // regions
    );
  }

  err = vkEndCommandBuffer(verifyCommandBuffer);
  if (err) goto cleanup;


  /**********  Submit the command buffer once per chunk of signatures  *********/

  VkFenceCreateInfo fenceCreateInfo = { .sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO };
  err = vkCreateFence(ctx->primaryDevice, &fenceCreateInfo, NULL, &fence);
  if (err) goto cleanup;

  VkQueue primaryQueue;
  vkGetDeviceQueue(ctx->primaryDevice, ctx->primaryDeviceQueueFamily, 0, &primaryQueue);

  uint32_t forsIndices[SLHVK_FORS_TREE_COUNT];
  for (uint32_t sigsChecked = 0; sigsChecked < signaturesLen; sigsChecked += signaturesChunkCount) {
    SlhvkSignatureVerifyRequest* signaturesMapped;
    err = vkMapMemory(
      ctx->primaryDevice,
      signaturesInputMemory,
      0,
      signaturesBufferSize,
      0,
      (void**) &signaturesMapped
    );
    if (err) goto cleanup;

    // Copy the signatures and their verification inputs to the device input memory
    for (uint32_t i = 0; i < signaturesChunkCount; i++) {
      uint32_t sigIndex = sigsChecked + i;
      if (sigIndex >= signaturesLen) break;

      slhvkDigestAndSplitMsg(
        signatures[sigIndex], // randomizer is first N bytes of signature,
        pkSeeds[sigIndex],
        pkRoots[sigIndex],
        contextStrings[sigIndex],
        contextStringSizes[sigIndex],
        messages[sigIndex],
        messageSizes[sigIndex],
        forsIndices,
        (uint64_t*) &signaturesMapped[i].treeAddress,
        &signaturesMapped[i].signingKeypairAddress
      );

      memcpy(signaturesMapped[i].pkSeed, pkSeeds[i], SLHVK_N);
      memcpy(signaturesMapped[i].signature, &signatures[i][SLHVK_N], SLHVK_SIGNATURE_SIZE - SLHVK_N);
      memcpy(signaturesMapped[i].forsIndices, forsIndices, sizeof(forsIndices));
    }
    vkUnmapMemory(ctx->primaryDevice, signaturesInputMemory);


    // Submit the command buffer to the queue to process this chunk of signatures.
    VkSubmitInfo submitInfo = {
      .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
      .commandBufferCount = 1,
      .pCommandBuffers = &verifyCommandBuffer,
    };
    err = vkQueueSubmit(primaryQueue, 1, &submitInfo, fence);
    if (err) goto cleanup;
    err = vkWaitForFences(ctx->primaryDevice, 1, &fence, VK_TRUE, 100e9);
    if (err) goto cleanup;
    err = vkResetFences(ctx->primaryDevice, 1, &fence);
    if (err) goto cleanup;

    // Read the verification output result PK roots
    uint8_t (*verifyResultsMapped)[N];
    err = vkMapMemory(
      ctx->primaryDevice,
      verifyResultsOutputMemory,
      0,
      verifyResultsBufferSize,
      0,
      (void**) &verifyResultsMapped
    );
    if (err) goto cleanup;
    size_t resultsLen = min(signaturesChunkCount, signaturesLen - sigsChecked);
    for (uint32_t i = 0; i < resultsLen; i++) {
      verifyResultsOut[sigsChecked + i] = memcmp(verifyResultsMapped[i], pkRoots[i], N);
    }
    vkUnmapMemory(ctx->primaryDevice, verifyResultsOutputMemory);
  }

cleanup:
  vkDestroyFence(ctx->primaryDevice, fence, NULL);
  vkDestroyBuffer(ctx->primaryDevice, signaturesBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, signaturesStagingBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, verifyResultsBuffer, NULL);
  vkDestroyBuffer(ctx->primaryDevice, verifyResultsStagingBuffer, NULL);
  vkFreeMemory(ctx->primaryDevice, signaturesBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, signaturesStagingBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, verifyResultsBufferMemory, NULL);
  vkFreeMemory(ctx->primaryDevice, verifyResultsStagingBufferMemory, NULL);

  return err;
}
