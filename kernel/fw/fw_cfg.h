#pragma once

#ifdef __cplusplus
extern "C" {
#endif 

#include "types.h"

struct fw_cfg_file {
    uint32_t size;
    uint16_t selector;
    uint16_t reserved;
    char name[56];
}__attribute__((packed));

bool fw_find_file(const char* search, struct fw_cfg_file *file);
void fw_cfg_dma_write(void* dest, uint32_t size, uint32_t ctrl);
void fw_cfg_dma_read(void* dest, uint32_t size, uint32_t ctrl);

#ifdef __cplusplus
}
#endif