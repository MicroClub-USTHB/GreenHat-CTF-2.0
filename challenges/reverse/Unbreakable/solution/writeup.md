We start by inspecting the given binary `Unbreakable` and encrypted flag `flag.txt.enc`:

```bash
┌──(kali㉿kali)-[~/…/challenges/reverse/Unbreakable/assets]
└─$ unzip Unbreakable.zip
Archive:  Unbreakable.zip
  inflating: Unbreakable
  inflating: flag.txt.enc

┌──(kali㉿kali)-[~/…/challenges/reverse/Unbreakable/assets]
└─$ file *
flag.txt.enc:    ASCII text, with no line terminators
Unbreakable:     ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a6762be0c7ccd11da428763620fd3f288e3de7d7, for GNU/Linux 3.2.0, not stripped
Unbreakable.zip: Zip archive data, made by v6.3 UNIX, extract using at least v2.0, last modified Jul 10 2025 17:14:10, uncompressed size 16496, method=deflate

┌──(kali㉿kali)-[~/…/challenges/reverse/Unbreakable/assets]
└─$ cat flag.txt.enc
1F105A761E036C6C1F0D0A710B4C5B6E1D275B770C277B704B4C52361A495C7F
```

We notice it's a 64 bits binary, and not stripped, so symbols are on, `flag.txt.enc` seems to be hex code.

We open the binary in IDA, after some name-tweaking we get:

```C
int __fastcall main(int argc, const char **argv, const char **envp){
  size_t length; // rax
  char output[48]; // [rsp+10h] [rbp-60h] BYREF
  char input[44]; // [rsp+40h] [rbp-30h] BYREF
  unsigned int DynamicKey; // [rsp+6Ch] [rbp-4h]

  memset(input, 0, 0x24uLL);
  memset(output, 0, sizeof(output));
  printf("Enter what you want to encrypt: ");
  fgets(input, 36, stdin);
  input[strcspn(input, "\n")] = 0;
  DynamicKey = generateDynamicKey(input);
  printf("Using key: 0x%08x\n", DynamicKey);
  encrypt(input, DynamicKey, output);
  printf("Encrypted output (hex): ");
  length = strlen(input);
  hexDump(output, length);
  return 0;
}

int generateDynamicKey(){
  unsigned int v0; // eax

  v0 = time(0LL);
  srand(v0);
  return rand();
}

char *__fastcall encrypt(const char *input, int key, char *output){
  char *result; // rax
  int i; // [rsp+2Ch] [rbp-24h]
  char *v6; // [rsp+30h] [rbp-20h]
  const char *v7; // [rsp+38h] [rbp-18h]

  v7 = input;
  v6 = output;
  for ( i = 0; i < strlen(input); i += 4 ){
    *(_DWORD *)v6 = key ^ *(_DWORD *)v7;
    v7 += 4;
    v6 += 4;
  }
  result = &output[strlen(input)];
  *result = 0;
  return result;
}

int __fastcall hexDump(char *buf, unsigned __int64 length){
  unsigned __int64 i; // [rsp+18h] [rbp-8h]

  for ( i = 0LL; i < length; ++i )
    printf("%02X", (unsigned __int8)buf[i]);
  return putchar(10);
}
```

We notice the binary encrypts the input using a time-dependent key.

It XORs each 4 bytes of the input with the key (`*(_DWORD *)v6 = key ^ *(_DWORD *)v7;`)

so it's like a XOR-based vigènere with a 4 bytes key.

Due to the impossibility of knowing the exact time of generating the key, and hence not being able to guess the seed used in `srand()`, we simply brute-force those 4 bytes, it shouldn't take more than 10 minutes with a correct script and 1 thread only.

Note:
 - Multi Threading can be used to fasten the operation.
 - Solve script in `/solution/solve.py`