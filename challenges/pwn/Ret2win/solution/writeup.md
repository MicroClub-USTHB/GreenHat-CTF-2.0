## Vulnerability Explanation

This binary is vulnerable to a classic buffer overflow. It asks the user:
`Whats the winners key to success:`

Then reads input into a fixed-size buffer on the stack. However, there's no bounds checking, allowing an attacker to overwrite the return address.

The goal is to overwrite the return address with the address of a function called win, which prints or gives access to the flag. This is known as a ret2win exploit.

## Exploitation Steps

1- Find the buffer overflow offset
The offset to overwrite EIP (on 32-bit) is 76 bytes.

2- Prepare the payload:
76 bytes of filler to reach return address.

3- Overwrite return address with the address of the win function.

4- Keep overwriting to function parameter which is places at OFFSET + EIP + 4 bytes chunk + parameter (**0xcafebabe** in our case)

### Flag : ghctf{$ucce$$fully_pwn3d_ret2win}
