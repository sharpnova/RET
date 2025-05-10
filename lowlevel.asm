section .text
global lowlevel_analyze

lowlevel_analyze:
    ; Input: rdi = pointer to buffer, rsi = size
    ; Output: rax = advanced checksum
    xor rax, rax
    test rsi, rsi
    jz .done
    xor rcx, rcx
    mov r8, 0x10001
.loop:
    movzx edx, byte [rdi + rcx]
    xor rax, rdx
    mul r8
    inc rcx
    cmp rcx, rsi
    jb .loop
.done:
    ret