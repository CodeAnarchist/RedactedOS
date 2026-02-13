#include "sysregs.h"

.global mmu_start
mmu_start:  //fn(uint64_t *ttbr1 x0, uint64_t *ttbr0 x1)
.type mmu_start, %function
    ldr x3, =MAIR_VALUE
    msr mair_el1, x3

    mrs x2, id_aa64mmfr0_el1
    and x2, x2, #0xF
    cmp x2, #6
    b.ls 1f
    mov x2, #6
1:
    lsl x2, x2, #32

    ldr x3, =TCR_VALUE_BASE
    orr x3, x3, x2
    msr tcr_el1, x3
    dsb ish
    isb

    msr ttbr1_el1, x0
    msr ttbr0_el1, x1
    
    mrs x0, sctlr_el1
    orr x0, x0, #0x1
    bic x0, x0, #(1 << 19)
    msr sctlr_el1, x0
    isb

    ldr x1, =HIGH_VA

    ldr x0, =ksp
    orr x0, x0, x1
    adrp x3, ksp
    str x0, [x3]

    ldr x0, =cpec
    orr x0, x0, x1
    adrp x3, cpec
    str x0, [x3]

    mov x0, sp
    orr x0, x0, x1
    mov sp, x0

    mov x0, x29
    orr x0, x0, x1
    mov x29, x0

    mov x0, x30
    orr x0, x0, x1
    mov x30, x0

    ldr x0, [sp, #8]
    orr x0, x0, x1
    str x0, [sp, #8]

    mrs x0, vbar_el1
    orr x0, x0, x1
    msr vbar_el1, x0
    
    ret