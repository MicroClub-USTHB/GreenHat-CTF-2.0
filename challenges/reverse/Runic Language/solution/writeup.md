When we open up the `runic.txt` from the attachement, we see:
```
bf000040004889f841bd35706c3448b90100320f010174476681c13f3048
81c9342372504889fb4883c30266c70363744883c004c6006649c1e5102c
03c740047b4d34354981c5797d000066c707676866ffcf66ffcf66ffcf89
4f0c49c1c5036683eb03c7400c77317a34b991a09bce83f1ff894f184d89
ecc7431272645f30bbdacec1ea81f3efbeadde895f1c4883c02048ffc848
ffc849c1cc0348ffc848ffc84c8920b83c00000048c1ef400f05
```

One cannot understand this code well at first, or even recognize its format or type, Reading the description well "runic language", and passing it through an LLM, we conclude it's a binary shellcode, probably from an `x86-64` architecture, running it through a disassembler ([cyberchef](https://gchq.github.io/CyberChef/) with its 'Disassembler x86', [defuse](https://defuse.ca/online-x86-assembler.htm), ...), we can get the original assembly code, I've chosen to use shell-storm, and so we get:
```assembly
0x0000000000000000:  BF 00 00 40 00                   mov     edi, 0x400000
0x0000000000000005:  48 89 F8                         mov     rax, rdi
0x0000000000000008:  41 BD 35 70 6C 34                mov     r13d, 0x346c7035
0x000000000000000e:  48 B9 01 00 32 0F 01 01 74 47    movabs  rcx, 0x477401010f320001
0x0000000000000018:  66 81 C1 3F 30                   add     cx, 0x303f
0x000000000000001d:  48 81 C9 34 23 72 50             or      rcx, 0x50722334
0x0000000000000024:  48 89 FB                         mov     rbx, rdi
0x0000000000000027:  48 83 C3 02                      add     rbx, 2
0x000000000000002b:  66 C7 03 63 74                   mov     word ptr [rbx], 0x7463
0x0000000000000030:  48 83 C0 04                      add     rax, 4
0x0000000000000034:  C6 00 66                         mov     byte ptr [rax], 0x66
0x0000000000000037:  49 C1 E5 10                      shl     r13, 0x10
0x000000000000003b:  2C 03                            sub     al, 3
0x000000000000003d:  C7 40 04 7B 4D 34 35             mov     dword ptr [rax + 4], 0x35344d7b
0x0000000000000044:  49 81 C5 79 7D 00 00             add     r13, 0x7d79
0x000000000000004b:  66 C7 07 67 68                   mov     word ptr [rdi], 0x6867
0x0000000000000050:  66 FF CF                         dec     di
0x0000000000000053:  66 FF CF                         dec     di
0x0000000000000056:  66 FF CF                         dec     di
0x0000000000000059:  89 4F 0C                         mov     dword ptr [rdi + 0xc], ecx
0x000000000000005c:  49 C1 C5 03                      rol     r13, 3
0x0000000000000060:  66 83 EB 03                      sub     bx, 3
0x0000000000000064:  C7 40 0C 77 31 7A 34             mov     dword ptr [rax + 0xc], 0x347a3177
0x000000000000006b:  B9 91 A0 9B CE                   mov     ecx, 0xce9ba091
0x0000000000000070:  83 F1 FF                         xor     ecx, 0xffffffff
0x0000000000000073:  89 4F 18                         mov     dword ptr [rdi + 0x18], ecx
0x0000000000000076:  4D 89 EC                         mov     r12, r13
0x0000000000000079:  C7 43 12 72 64 5F 30             mov     dword ptr [rbx + 0x12], 0x305f6472
0x0000000000000080:  BB DA CE C1 EA                   mov     ebx, 0xeac1ceda
0x0000000000000085:  81 F3 EF BE AD DE                xor     ebx, 0xdeadbeef
0x000000000000008b:  89 5F 1C                         mov     dword ptr [rdi + 0x1c], ebx
0x000000000000008e:  48 83 C0 20                      add     rax, 0x20
0x0000000000000092:  48 FF C8                         dec     rax
0x0000000000000095:  48 FF C8                         dec     rax
0x0000000000000098:  49 C1 CC 03                      ror     r12, 3
0x000000000000009c:  48 FF C8                         dec     rax
0x000000000000009f:  48 FF C8                         dec     rax
0x00000000000000a2:  4C 89 20                         mov     qword ptr [rax], r12
0x00000000000000a5:  B8 3C 00 00 00                   mov     eax, 0x3c
0x00000000000000aa:  48 C1 EF 40                      shr     rdi, 0x40
0x00000000000000ae:  0F 05                            syscall 
```

We notice it's an obfuscated assembly code, loading the flag into memory using complex operations to hide its original meaning, such as `ROL`, `XOR`, ...

We start by simplifying the additional and unecessary instructions that only make the code more unreadable, such as removing the `exit(0)` at the end and some of the following transformations:

```
DEC RAX                 
DEC RAX                 SUB RAX, 4
ROR R12,03      -->     ROR R12, 03
DEC RAX
DEC RAX
```

And

```
MOV RCX,477401010F320001
ADD CX,303F                 -->     MOV RCX, 477401015F723374
OR RCX,0000000050722334
```

well you got the drill, just simplifications and re-ordering to the obfuscated and overly-complexe code, we end up with something similar to:

```
mov     edi, 0x400000
mov     word ptr [rdi], 0x6867
mov     word ptr [rdi + 2], 0x7463
mov     byte ptr [rdi + 4], 0x66
mov     dword ptr [rdi + 5], 0x35344d7b
mov     dword ptr [rdi + 9], 0x5f723374
mov     dword ptr [rdi + 0xd], 0x347a3177
mov     dword ptr [rdi + 0x11], 0x305f6472
mov     dword ptr [rdi + 0x15], 0x31645f6e
mov     dword ptr [rdi + 0x19], 0x346c7035
mov     qword ptr [rdi + 0x1d], 0x7d79
```

We now pass the values in order to cyberchef, with recipes `Swap_endianness('Hex',4,false)` then `From_Hex('Auto')` for each line separately:
```
0x6867          -->         gh
0x7463          -->         ct
0x66            -->         f
0x35344d7b      -->         {M45
                .
                .
                .
0x346c7035      -->         5pl4
0x7d79          -->         y}
```

After grouping them all we find: `ghctf{M45t3r_w1z4rd_0n_d15pl4y}`