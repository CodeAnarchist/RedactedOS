#pragma once

#include "types.h"
#include "ui/graphic_types.h"
#include "keypress.h"
#include "std/string.h"
#include "net/network_types.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void printl(const char *str);

extern uintptr_t malloc(size_t size);
extern void free(void *ptr, size_t size);

extern bool read_key(keypress *kp);

extern void sleep(uint64_t time);
extern void halt();

extern void clear_screen(color color);
extern void gpu_flush_data();

extern gpu_size* gpu_screen_size();
extern uint32_t gpu_char_size(uint32_t scale);

extern void draw_primitive_pixel(gpu_point *p, color color);
extern void draw_primitive_line(gpu_point *p0, gpu_point *p1, color color);
extern void draw_primitive_rect(gpu_rect *r, color color);
extern void draw_primitive_char(gpu_point *p, char c, uint32_t scale, uint32_t color);
extern void draw_primitive_string(string *text, gpu_point *p, uint32_t scale, uint32_t color);

extern uint64_t get_time();

extern bool bind_port(uint16_t port);
extern bool unbind_port(uint16_t port);
extern void send_packet(NetProtocol protocol, uint16_t port, network_connection_ctx *destination, void* payload, uint16_t payload_len);
extern bool read_packet(sizedptr *ptr);

void printf(const char *fmt, ...);

#ifdef __cplusplus
}
#endif