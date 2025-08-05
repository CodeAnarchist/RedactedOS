#pragma once 

#include "../gpu_driver.hpp"

class VideoCoreGPUDriver : public GPUDriver {
public:
    static VideoCoreGPUDriver* try_init(gpu_size preferred_screen_size);
    VideoCoreGPUDriver(){}
    bool init(gpu_size preferred_screen_size) override;

    void flush() override;

    void clear(color color) override;
    void draw_pixel(uint32_t x, uint32_t y, color color) override;
    void fill_rect(uint32_t x, uint32_t y, uint32_t width, uint32_t height, color color) override;
    void draw_line(uint32_t x0, uint32_t y0, uint32_t x1,uint32_t y1, color color) override;
    void draw_char(uint32_t x, uint32_t y, char c, uint32_t scale, uint32_t color) override;
    gpu_size get_screen_size() override;
    void draw_string(string s, uint32_t x, uint32_t y, uint32_t scale, uint32_t color) override;
    uint32_t get_char_size(uint32_t scale) override;
    ~VideoCoreGPUDriver() = default;
    
private: 
    gpu_size screen_size;
    uintptr_t framebuffer;
    uintptr_t back_framebuffer;

    void* mem_page;

    uint8_t bpp;
    uint32_t stride;
};