#pragma once

#include "types.h"
#include "process/process.h"

typedef enum {
    INTERRUPT,
    YIELD,
    HALT,
} ProcSwitchReason;

#define MAX_PROCS 16

void switch_proc(ProcSwitchReason reason);
void start_scheduler();
void save_context_registers();
void save_return_address_interrupt();
void init_main_process();
process_t* init_process();
void save_syscall_return(uint64_t value);
void process_restore();

void stop_process(uint16_t pid);
void stop_current_process();

void name_process(process_t *proc, const char *name);

void sleep_process(uint64_t msec);
void wake_processes();

#ifdef __cplusplus
extern "C" {
#endif

process_t* get_current_proc();
process_t* get_proc_by_pid(uint16_t pid);
uint16_t get_current_proc_pid();

uintptr_t get_current_heap();
bool get_current_privilege();
#ifdef __cplusplus
}
#endif

uint16_t process_count();
process_t *get_all_processes();

extern uint64_t ksp;