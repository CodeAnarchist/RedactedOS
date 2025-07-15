#pragma once

#include "types.h"
#include "memory_types.h"

#define ALIGN_4KB 0x1000
#define ALIGN_16B 0x10
#define ALIGN_64B 0x40
#define PAGE_SIZE 4096

void page_alloc_enable_verbose();
void page_allocator_init();

#ifdef __cplusplus
extern "C" {
#endif
void* alloc_page(uint64_t size, bool kernel, bool device, bool full);
void free_page(void* ptr, uint64_t size);
void mark_used(uintptr_t address, size_t pages);

void* allocate_in_page(void *page, uint64_t size, uint16_t alignment, bool kernel, bool device);
void free_from_page(void* ptr, uint64_t size);

int count_pages(uint64_t i1,uint64_t i2);

void free_sized(sizedptr ptr);

#ifdef __cplusplus
}
#endif