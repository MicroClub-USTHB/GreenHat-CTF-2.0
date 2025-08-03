## Vulnerability Explanation

The program reads up to 128 bytes into a fixed-size 64-byte buffer and then checks the buffer length:

```c
read(0, buff, 128);
if (strlen(buff) > 64) {
    printf("Too many characters, fiha khir\n");
    exit(0);
}
```

However, the `read` will happily write up to 128 bytes, overflowing past `buff` and into the adjacent `check` variable on the stack. Since there’s no write protection, we can overwrite `check`. Later the code does:

```c
if (check == 0xdeadbeef) {
    flag();
}
```

By overflowing and setting `check` to `0xdeadbeef`, we trigger `flag()` and print the flag.

## Exploitation Steps

1. **Determine overwrite offset**

   - The buffer is 64 bytes.
   - There’s a null‐byte check via `strlen`, so we ensure our padding ends with a `\x00` within the first 64 bytes to pass the length check.
   - After that null, we can use extra bytes (up to 128 total) to reach and overwrite `check`.

2. **Construct payload**

   - **64 bytes** for `buff`: use `63` `'A'`s then a `\x00` to keep `strlen(buff)` at 63.
   - **12 bytes** of filler to skip saved registers and reach `check`.
   - **4-byte value** `0xdeadbeef` to overwrite `check`.

   ```python
   padding = b'A' * 63 + b'\x00'
   filler  = b'B' * 12
   target  = p32(0xdeadbeef)
   payload = padding + filler + target
   ```

3. **Send the payload**
   The program prompts:

   ```
   Kol 3otla
   ```

   We send our crafted payload, which overflows and sets `check` correctly.

4. **Read the flag**
   After overwriting, execution reaches `flag()` and prints the flag. We can then capture it from the output.

### Flag: ghctf{k0l_33307l4_f1h4_buffer_0v3rfl0w}
