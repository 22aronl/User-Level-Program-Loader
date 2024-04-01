
# code for switch_elf (uint64_t entry, void* stack)
.global switch_elf
switch_elf:
    mov %rsi, %rsp
    push %rdi

    xor %rdi, %rdi
    xor %rsi, %rsi
    xor %rbx, %rbx
    xor %rdx, %rdx
    xor %rcx, %rcx
    xor %rax, %rax
    xor %r8, %r8
    xor %r9, %r9
    xor %r10, %r10
    xor %r11, %r11
    xor %r12, %r12
    xor %r13, %r13
    xor %r14, %r14
    xor %r15, %r15
    xor %rbp, %rbp

    ret