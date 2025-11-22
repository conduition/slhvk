#include <stdint.h>
#include <string.h>
#include <vulkan/vulkan.h>

#include "context.h"
#include "hashing.h"
#include "keygen.h"
#include "sha256.h"

static void prepstate(ShaContext* shaCtx, const uint8_t pkSeed[N]) {
  uint8_t block[64] = {0};
  memcpy(block, pkSeed, N);
  slhvkSha256Init(shaCtx);
  slhvkSha256Update(shaCtx, block, 64);
}

int slhvkSignPure(
  SlhvkContext ctx,
  uint8_t const skSeed[N],
  uint8_t const skPrf[N],
  uint8_t const pkSeed[N],
  uint8_t const pkRoot[N],
  uint8_t const addrnd[N],
  uint8_t const* contextString,
  uint8_t contextStringSize,
  uint8_t const* rawMessage,
  size_t rawMessageSize,
  const SlhvkCachedRootTree cachedXmssRootTree,
  uint8_t signatureOutput[SLHVK_SIGNATURE_SIZE]
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

  uint32_t forsIndices[SLHVK_FORS_TREE_COUNT];
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
    CommonSigningInputs* mapped = NULL;
    err = vkMapMemory(
      devices[i],
      memories[i],
      0, // offset
      sizeof(CommonSigningInputs),
      0, // flags
      (void**) &mapped
    );
    if (err) goto cleanup;

    memcpy(&mapped->sha256State[0], shaCtxInitial.state, sizeof(uint32_t) * 8);

    // Copy the skSeed into a big-endian encoded u32 array
    for (size_t i = 0; i < SLHVK_HASH_WORDS; i++) {
      size_t i4 = i * sizeof(uint32_t);
      mapped->skSeed[i] = ((uint32_t) skSeed[i4] << 24) | ((uint32_t) skSeed[i4 + 1] << 16) |
                          ((uint32_t) skSeed[i4 + 2] << 8) | (uint32_t) skSeed[i4 + 3];
    }
    mapped->treeAddress = treeAddress;
    mapped->signingKeypairAddress = signingKeypairAddress;
    mapped->cachedTreeLayers = (cachedXmssRootTree == NULL ? 0 : 1);
    vkUnmapMemory(devices[i], memories[i]);
  }

  // Start the command buffer which may be used to copy the root XMSS tree to the correct
  // region of the XMSS nodes buffer.
  err = vkResetCommandBuffer(ctx->primaryXmssRootTreeCopyCommandBuffer, 0);
  if (err) goto cleanup;

  VkCommandBufferBeginInfo cmdBufBeginInfo = {
    .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
  };
  err = vkBeginCommandBuffer(ctx->primaryXmssRootTreeCopyCommandBuffer, &cmdBufBeginInfo);
  if (err) goto cleanup;

  // Copy the cached root tree to the xmss nodes buffer.
  if (cachedXmssRootTree != NULL) {
    VkBufferCopy regions = {
      .size = SLHVK_XMSS_CACHED_TREE_SIZE,
      .dstOffset = N * SLHVK_XMSS_LEAVES * (SLHVK_HYPERTREE_LAYERS - 1),
    };
    vkCmdCopyBuffer(
      ctx->primaryXmssRootTreeCopyCommandBuffer,
      cachedXmssRootTree->buffer,  // src
      ctx->primaryXmssNodesBuffer, // dest
      1, // region count
      &regions // regions
    );
  }

  // Signal the main signing command buffer that it is safe to continue.
  vkCmdSetEvent(
    ctx->primaryXmssRootTreeCopyCommandBuffer,
    ctx->primaryXmssRootTreeCopyDoneEvent,
    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT
  );

  err = vkEndCommandBuffer(ctx->primaryXmssRootTreeCopyCommandBuffer);
  if (err) goto cleanup;

  VkCommandBuffer signingCommandBuffers[2] = {
    ctx->primaryXmssRootTreeCopyCommandBuffer,
    ctx->primaryHypertreePresignCommandBuffer,
  };

  VkSubmitInfo xmssSubmitInfo = {
    .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
    .commandBufferCount = 2,
    .pCommandBuffers = signingCommandBuffers,
  };

  // Submit the XMSS precomputation shaders right away, because they take the most runtime.
  err = vkQueueSubmit(primaryQueue, 1, &xmssSubmitInfo, primaryFence);
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
  VkSubmitInfo submitInfo = {
    .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
    .commandBufferCount = 1,
    .pCommandBuffers = &ctx->secondaryForsCommandBuffer,
  };
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

  uint32_t wotsMessage[SLHVK_WOTS_CHAIN_COUNT];
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
  for (int i = 0; i < SLHVK_WOTS_CHAIN_COUNT; i++) {
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
  uint8_t forsSig[SLHVK_FORS_SIGNATURE_SIZE];
  VkDeviceMemory forsSigMemory = (ctx->secondaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)
    ? ctx->secondaryForsSignatureBufferDeviceLocalMemory
    : ctx->secondaryForsSignatureBufferHostVisibleMemory;
  uint8_t* mappedSignature = NULL;
  err = vkMapMemory(ctx->secondaryDevice, forsSigMemory, 0, SLHVK_FORS_SIGNATURE_SIZE, 0, (void**) &mappedSignature);
  if (err) goto cleanup;
  memcpy(&signatureOutput[N], mappedSignature, SLHVK_FORS_SIGNATURE_SIZE);
  memcpy(forsSig, mappedSignature, SLHVK_FORS_SIGNATURE_SIZE);
  vkUnmapMemory(ctx->secondaryDevice, forsSigMemory);

  // Copy the hypertree signature to the output pointer
  VkDeviceMemory hypertreeSigMemory = (ctx->primaryDeviceLocalMemoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)
    ? ctx->primaryHypertreeSignatureBufferDeviceLocalMemory
    : ctx->primaryHypertreeSignatureBufferHostVisibleMemory;
  err = vkMapMemory(ctx->primaryDevice, hypertreeSigMemory, 0, SLHVK_HYPERTREE_SIGNATURE_SIZE, 0, (void**) &mappedSignature);
  if (err) goto cleanup;
  memcpy(&signatureOutput[N + SLHVK_FORS_SIGNATURE_SIZE], mappedSignature, SLHVK_HYPERTREE_SIGNATURE_SIZE);
  vkUnmapMemory(ctx->primaryDevice, hypertreeSigMemory);

cleanup:
  vkDestroyFence(ctx->primaryDevice, primaryFence, NULL);
  vkDestroyFence(ctx->secondaryDevice, secondaryFence, NULL);
  return err;
}
