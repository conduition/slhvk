#pragma once
#include <vulkan/vulkan.h>

#include "slhvk.h"

typedef struct SlhvkCachedRootTree_T {
  SlhvkContext ctx;
  VkBuffer buffer;
  VkDeviceMemory memory;
  VkMemoryPropertyFlags memFlags;
} SlhvkCachedRootTree_T;
