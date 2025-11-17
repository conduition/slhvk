#pragma once
#include <stdint.h>
#include <vulkan/vulkan.h>

uint32_t slhvkNumWorkGroups(uint32_t threadsCount);

int slhvkFindDeviceComputeQueueFamily(VkPhysicalDevice physicalDevice);

int slhvkAllocateBufferMemory(
  VkDevice device,
  VkPhysicalDevice physicalDevice,
  VkBuffer buffer,
  VkMemoryPropertyFlags desiredMemoryFlags,
  VkMemoryPropertyFlags* actualMemoryFlags,
  VkDeviceMemory* memoryPtr
);

int slhvkSetupDescriptorSetLayout(
  VkDevice device,
  uint32_t bindingCount,
  VkDescriptorSetLayout* descriptorSetLayout
);

void slhvkBindBuffersToDescriptorSet(
  VkDevice device,
  const VkBuffer* buffers,
  uint32_t buffersCount,
  VkDescriptorSet descriptorSet
);
