## Vulnerability Explanation

This challenge maps an executable, writable memory region and then directly jumps into whatever the user reads in. Specifically:

```c
void* shellcode = mmap(NULL, 22,
    PROT_EXEC | PROT_WRITE,
    MAP_PRIVATE | MAP_ANON,
    -1, 0);

puts("Enter the code you want to execute: ");
read(0, shellcode, 22);
goto *shellcode;
```

Arbitrary code execution: There is no sandboxing or validation of the code read. Anything you send becomes executable shellcode.

X86_64 context: The binary is 64-bit, so your shellcode must use the correct 64-bit calling conventions and syscall numbers.

## Exploitation Steps

1- The program reads 22 bytes from the user, we need a short shellcode that is at max 22 bytes of length.
we can get it from [here](https://systemoverlord.com/2016/04/27/even-shorter-shellcode.html).

2- Send the shellcode after program prompts:
`Enter the code you want to execute:`

Simply send the assembled bytes. They are written into an executable mmap region and immediately jumped to.

3- Interact and retrieve flag after shellcode runs.

### Flag: ghctf{$h3llc0d1n6_1s_s0_8uch_fun}
