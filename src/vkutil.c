#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <vulkan/vulkan.h>

#include "slhvk.h"

uint32_t slhvkNumWorkGroups(uint32_t threadsCount) {
  return (threadsCount + SLHVK_DEFAULT_WORK_GROUP_SIZE - 1) / SLHVK_DEFAULT_WORK_GROUP_SIZE;
}

int slhvkFindDeviceComputeQueueFamily(VkPhysicalDevice physicalDevice) {
  uint32_t queueFamilyCount = 0;
  vkGetPhysicalDeviceQueueFamilyProperties(physicalDevice, &queueFamilyCount, NULL);
  VkQueueFamilyProperties* queueFamilies = malloc(queueFamilyCount * sizeof(VkQueueFamilyProperties));
  vkGetPhysicalDeviceQueueFamilyProperties(physicalDevice, &queueFamilyCount, queueFamilies);
  int found = -1;
  for (uint32_t i = 0; i < queueFamilyCount; i++) {
    if (queueFamilies[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
      found = (int) i;
      break;
    }
  }
  free(queueFamilies);
  return found;
}

int slhvkAllocateBufferMemory(
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

int slhvkSetupDescriptorSetLayout(
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
void slhvkBindBuffersToDescriptorSet(
  VkDevice device,
  const VkBuffer* buffers,
  uint32_t buffersCount,
  VkDescriptorSet descriptorSet
) {
  for (uint32_t i = 0; i < buffersCount; i++) {

    // Specify the buffer to bind to the descriptor.
    VkDescriptorBufferInfo bufferInfo = {
      .buffer = buffers[i],
      .offset = 0,
      .range = VK_WHOLE_SIZE,
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
