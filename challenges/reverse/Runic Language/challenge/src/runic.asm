section .text
    global _start

_start:
    ; Allocate memory area
    mov rdi, 0x400000
    mov rax, rdi

    ; Store the flag "ghctf{M45t3r_w1z4rd_0n_d15pl4y}"
    ; in reverse chunks due to little endian

    mov r13, 0x346c7035

    mov rcx, 0x477401010f320001
    add cx,  0x303f
    or  rcx, 0x1800606450722334

    mov rbx, rdi
    add rbx, 2
    mov word [rbx],     0x7463

    add rax, 4
    mov byte [rax],     0x66

    shl r13, 16

    sub al, 3
    mov dword [rax+4],  0x35344d7b

    add r13, 0x7d79

    mov word [rdi],    0x6867

    dec di
    dec di
    dec di

    mov dword [rdi+12], ecx

    rol r13, 3
    sub bx, 3

    mov dword [rax+12], 0x347a3177

    mov ecx, 0xce9ba091
    xor ecx, 0xffffffff
    mov dword [rdi+24], ecx

    mov r12, r13

    mov dword [rbx+18], 0x305f6472
    mov ebx, 0xeac1ceda
    xor ebx, 0xdeadbeef

    mov dword [rdi+28], ebx

    add rax, 32
    dec rax
    dec rax

    ror r12, 3

    dec rax
    dec rax
    mov qword [rax], r12

; COMMENT OUT TO TRY POC, REPLACE ALL '0x400000' with 'RSP'
;    ; write(1, rdi, 34)
;    mov rax, 1          ; syscall: write
;    mov rdi, 1          ; fd: stdout
;    mov rsi, 0x400000   ; buffer
;    mov rdx, 31         ; length
;    syscall

    ; exit(0)
    mov rax, 0x3c       ; syscall: write
    shr rdi, 64         ; rdi <-- 0
    syscall