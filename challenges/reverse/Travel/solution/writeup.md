After First inspecting the file using the `file` command:
```bash
└─$ file travel 
travel: ELF 32-bit LSB pie executable, Intel i386, version 1 (GNU/Linux), BuildID[sha1]=e7c212caefbf43ea5a7fe04a410fa21a8c90c30f, for GNU/Linux 3.2.0, statically linked, no section header
```

We notice it this weird 32-bits binary, with 'no section header', what ever that is, we go and try to find some useful strings:
```bash
└─$ strings travel 
'UPX!
^v`'
/libd-
nux.s
o.2/
I3`_8J/"
C6$C1
...
UPX-5.0 wants memfd_create(), or needs /dev/shm(,O_TMPFILE,)
...
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 5.01 Copyright (C) 1996-2025 the UPX Team. All Rights Reserved. $
...
```
Those strings say it all, this binary was packed using the famous [UPX Packer](https://upx.github.io/), specifically the [5.1 version](https://github.com/upx/upx/releases/tag/v5.0.1).

We must download UPX of that version or newer, 5.1 is the latest version at the time of writing this writeup.

And then we unpack it and notice it became a regular binary we can work with:
```bash
└─$ upx-5.0.1-amd64_linux/upx -d travel -o travel.unpacked
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2025
UPX 5.0.1       Markus Oberhumer, Laszlo Molnar & John Reiser    May 6th 2025

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     15616 <-      7564   48.44%   linux/i386    travel.unpacked

Unpacked 1 file.

└─$ file travel.unpacked 
travel.unpacked: ELF 32-bit LSB pie executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=e7c212caefbf43ea5a7fe04a410fa21a8c90c30f, for GNU/Linux 3.2.0, not stripped
```

We try to see what it's doing:
```bash
└─$ ./travel.unpacked 
What do you do when you're travelling travelling ? aaaa
Wrong!
```

Ok so a simple password checker I guess, we open it in IDA:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _DWORD *v4; // [esp+0h] [ebp-1Ch]

  setup();
  v4 = mmap((void *)0x7000000, code_len, 7, 50, -1, 0);
  if ( v4 != (_DWORD *)-1 )
  {
    decrypt_code();
    *v4 = code[0];
    *(_DWORD *)((char *)v4 + 287) = *(_DWORD *)((char *)&code[71] + 3);
    qmemcpy(
      (void *)((unsigned int)(v4 + 1) & 0xFFFFFFFC),
      (const void *)((char *)code - ((char *)v4 - ((unsigned int)(v4 + 1) & 0xFFFFFFFC))),
      4 * ((((unsigned int)v4 - ((unsigned int)(v4 + 1) & 0xFFFFFFFC) + 291) & 0xFFFFFFFC) >> 2));
    __asm { jmp     [ebp+var_1C] }
  }
  perror("mmap failed");
  return 1;
}
```

Ok so we notice it is opening a new `RWX` page at address `0x7000000` using `mmap()`, of length `code_len`, which is a global variable:
```C
.data:00004164 code_len        dd 291
```

for the `decrypt_code` function, we see it is manipulating a global variable's memory using what seems like a ROL (left rotate) and XOR with a static `0xAA`
```C
Elf32_Dyn **decrypt_code()
{
  Elf32_Dyn **result; // eax
  unsigned int i; // [esp+Ch] [ebp-8h]

  result = &GLOBAL_OFFSET_TABLE_;
  for ( i = 0; i <= 0x122; ++i )
  {
    *((_BYTE *)code + i) = (*((unsigned __int8 *)code + i) >> 6) | (4 * *((_BYTE *)code + i));
    *((_BYTE *)code + i) ^= 0xAAu;
  }
  return result;
}
```

and `code` is:
```C
.data:00004040 code            dd 0AAAAAB84h, 0AAEA44AAh, 0B4C4AAAAh, 46BAAAAh, 0AAAAAAA7h
.data:00004054                 dd 6A848AD9h, 44AAAAAAh, 0AAAAAAAAh, 0AAAA52C4h, 0AA63046Bh
...
```

and then it copies that `code` into our newly created map at `0x7000000` in the rest of `main()` using `qmemcpy` (consider it same as `memcpy`)

after setting the type of `code` to `_BYTE [2092]` as deduced and setting return value of `decrypt_code` to `void` (after tracing the assembly, we deduce that the return value holds no meaning), it becomes clear:
```C
void decrypt_code()
{
  unsigned int i; // [esp+Ch] [ebp-8h]

  for ( i = 0; i <= 0x122; ++i )
  {
    code[i] = ((unsigned __int8)code[i] >> 6) | (4 * code[i]);
    code[i] ^= 0xAAu;
  }
}
```

Ok so until now, the program reads a static code from global memory, decrypts it using ROL() and XOR, and then copies it into the newly created memory.
Let's try to see its behaviour in gdb.
After we disassemble this `main`, we notice this jump straight after completing the copy process:
```C
0x00001355 <+160>:   jmp    DWORD PTR [ebp-0x1c]
```
let's break into it and see the contents of `DWORD PTR [ebp-0x1c]` at runtime:
```c
pwndbg> b *main+160
Breakpoint 1 at 0x1355
pwndbg> r
Starting program: /home/kali/CTFs/MC/internal-ctf-2.0/challenges/reverse/Travel/solution/travel.unpacked 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Inferior 1 (process 22786) exited with code 01]
```

ooh, it existed directly, now that's weird, ok maybe we should watch what it is doing inside every function.
and then we notice this `setup` function we ignored earlier:
```C
int setup()
{
  int result; // eax

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  result = ptrace(PTRACE_TRACEME, 0, 0, 0);
  if ( result == -1 )
    exit(1);
  return result;
}
```

now that makes sense, Anti-Debugging using `ptrace`, we can simply jump the `setup` call, as it is doing nothing useful anyway, we use these commands to manually jump that call:
```C
b *main + 31
b *main+160
r
set $eip=0x565562d9
```

and voila!, we 'bypassed' it, now we continue our dynamic analysis.

we notice that jump contained the address of the map, so we are jumping to our code:
```C
 ► 0x56556355 <main+160>    jmp    dword ptr [ebp - 0x1c]      <0x7000000>
```

and we get this assembly code:
```C
pwndbg> x/32i $eip
=> 0x7000000:   mov    eax,0x4
   0x7000005:   mov    ebx,0x1
   0x700000a:   mov    ecx,0x7000078
   0x700000f:   mov    edx,0x34
   0x7000014:   int    0x80
   0x7000016:   mov    eax,0x3
   0x700001b:   mov    ebx,0x0
   0x7000020:   mov    ecx,0x70000e3
   0x7000025:   mov    edx,0x27
   0x700002a:   int    0x80
   0x700002c:   mov    esi,0x70000e3
   0x7000031:   mov    edi,0x70000bc
   0x7000036:   mov    ecx,0x27
   0x700003b:   dec    ecx
   0x700003c:   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
   0x700003e:   jne    0x7000058
   0x7000040:   mov    eax,0x4
   0x7000045:   mov    ebx,0x1
   0x700004a:   mov    ecx,0x70000ac
   0x700004f:   mov    edx,0x9
   0x7000054:   int    0x80
   0x7000056:   jmp    0x700006e
   0x7000058:   mov    eax,0x4
   0x700005d:   mov    ebx,0x1
   0x7000062:   mov    ecx,0x70000b5
   0x7000067:   mov    edx,0x7
   0x700006c:   int    0x80
   0x700006e:   mov    eax,0x1
   0x7000073:   xor    ebx,ebx
   0x7000075:   int    0x80
   0x7000077:   add    BYTE PTR [edi+0x68],dl
```

Understanding it manually, or running it through an LLM, makes us understand that it is doing the following:
- prints something from 0x7000078 # "What do you do when you're travelling travelling ? "
- reads 0x26 (38 bytes) into 0x70000e3
- compares between our input (0x70000e3) and some address (0x70000bc)
- prints strings depending on result
- exists with status 0

We inspect the compared string, probably the expected input:
```C
pwndbg> x/s 0x70000bc
0x70000bc:      "ghctf{0f_c0ur53_Y0u_P4ck_P4ck!_0f0f0f}"
```

and the flag it was.

## RECAP
- We found a binary packed using UPX 5.1, we unpacked it.
- Statically analyzed it using IDA, it loads some shellcode into newly created page of memory after decrypting it.
- Runs the previously mentioned code by jumping into it.
- Dynamically analyzed the injected shellcode, to see its behaviour, after skipping through Anti-Debugger Mitigations.
- The injected shellcode reads input and compares it to the plaintext flag.
- We examine live memory and get the flag "ghctf{0f_c0ur53_Y0u_P4ck_P4ck!_0f0f0f}"