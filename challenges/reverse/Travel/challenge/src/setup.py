import os

asm_code = \
"""section .text
    global _start

_start:
    ; print prompt
    mov eax, 4
    mov ebx, 1
    mov ecx, prompt
    mov edx, prompt_len
    int 0x80

    ; read input
    mov eax, 3
    mov ebx, 0
    mov ecx, buffer
    mov edx, flag_len
    int 0x80

    ; compare
    mov esi, buffer
    mov edi, flag
    mov ecx, flag_len
    dec ecx
    repe cmpsb
    jne wrong

    ; correct
    mov eax, 4
    mov ebx, 1
    mov ecx, correct
    mov edx, correct_len
    int 0x80
    jmp exit

wrong:
    mov eax, 4
    mov ebx, 1
    mov ecx, wrong_msg
    mov edx, wrong_len
    int 0x80

exit:
    mov eax, 1
    xor ebx, ebx
    int 0x80

section .data
prompt db "What do you do when you're travelling travelling ? ", 0
prompt_len equ $ - prompt

correct db "Correct!", 0
correct_len equ $ - correct

wrong_msg db "Wrong!", 0
wrong_len equ $ - wrong_msg

flag db "ghctf{0f_c0ur53_Y0u_P4ck_P4ck!_0f0f0f}", 0
flag_len equ $ - flag

buffer times 64 db 0"""

open('shellcode.asm', 'w').write(asm_code)


linker_script = \
"""SECTIONS {
    . = 0x7000000;
    .text : { *(.text) }
    .data : { *(.data) }
}"""

open("link.ld", "w").write(linker_script)

os.system("nasm -f elf32 -o shellcode.o shellcode.asm")
os.system("ld -m elf_i386 -T link.ld -o shellcode shellcode.o")
os.system("objcopy -O binary --only-section=.text --only-section=.data shellcode shellcode.extracted")

with open("shellcode.extracted", "rb") as f:
    data = f.read()

def ror(val, r_bits):
    return ((val >> r_bits) | (val << (8 - r_bits))) & 0xFF

def encrypt_byte(b, xor_key):
    rotated = ror(b, 2)
    return rotated ^ xor_key

XOR_KEY = 0xAA

encrypted = []

encrypted = bytes([ (( b << 6 | b >> 2) ^ XOR_KEY) & 0xFF for b in data])

# Output for C with 8 bytes per line
step = 16
print("unsigned char code[] = {")
for i in range(0, len(encrypted), step):
    line = ", ".join(f"0x{b:02X}" for b in encrypted[i:i+step])
    print("    " + line + ("," if i + step < len(encrypted) else ""))
print("};")
print(f"size_t code_len = sizeof(code);")

os.system("rm shellcode.asm")
os.system("rm shellcode.o")
os.system("rm shellcode")
os.system("rm shellcode.extracted")
os.system("rm link.ld")