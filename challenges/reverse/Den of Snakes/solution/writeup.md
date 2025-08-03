## Reconnaissance
We start by our usual inspection of the given binary:
```bash
└─$ file snakes
snakes: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=eb586756c39e4efd29c393a8b324b3af04fd9a90, stripped
```

Oh oh, another stripped binary, we see if it there is any useful strings or if it was packed by UPX:
```bash
└─$ strings snakes
/lib64/ld-linux-x86-64.so.2
...
blib-dynload/resource.cpython-313-x86_64-linux-gnu.so
...
9libpython3.13.so.1.0
...
pydata
```

```bash
└─$ strings snakes | grep -i upx

```

Ok so this binary is related to python, and wasn't packed using UPX, at least not in the traditional way.

## Dynamic Analysis
we try running it dynamically to see what it does:
```bash
└─$ ./snakes
Enter the flag: aaaa
Incorrect.
```

Ok, so a simple crackme, checks for flag and tells us if it's correct.

## Static Analysis

We try opening the binary in IDA, we get the usual `start` that has `_libc_start_main`, because the binary is stripped of its symbols, so no main function to detect:
```C
// positive sp value has been detected, the output may be wrong!
void __fastcall __noreturn start(__int64 a1, __int64 a2, void (*a3)(void))
{
  __int64 v3; // rax
  int v4; // esi
  __int64 v5; // [rsp-8h] [rbp-8h] BYREF
  char *retaddr; // [rsp+0h] [rbp+0h] BYREF

  v4 = v5;
  v5 = v3;
  _libc_start_main(main, v4, &retaddr, init, fini, a3, &v5);
  __halt();
}
```

We go into `main`, and into `sub_404A10`, as it's the only function executed by main, so it is expected to do the work:
```C
__int64 __fastcall sub_404A10(unsigned int *a1)
{
  char *v1; // r15
  char *v2; // rbp
  const char *v4; // r13
  ssize_t v5; // rax
  __int64 v6; // rax
  const char *v7; // r13
  __int64 v8; // rax
...
  v1 = (char *)a1 + 12361;
  v2 = (char *)(a1 + 8);
  v120 = __readfsqword(0x28u);
  v4 = (const char *)**((_QWORD **)a1 + 1);
  v5 = readlink("/proc/self/exe", (char *)a1 + 32, 0xFFFuLL);
  if ( v5 != -1 )
...
```

Ok very complicated stuff, scrolling a bit we notice some weird strings:
```C
    sub_404170(
      (unsigned int)"Could not load PyInstaller's embedded PKG archive from the executable (%s)\n",
      (_DWORD)a1 + 32,
      v21,
      v22,
      v23,
      v24);

    sub_404170(
      (unsigned int)"Could not side-load PyInstaller's PKG archive from external file (%s)\n",
      (_DWORD)a1 + 4128,
      v26,
      v27,
      v28,
      v29);

    v30 = (char *)sub_408520("PYINSTALLER_SUPPRESS_SPLASH_SCREEN");

  if ( v10 )
  {
    ptr = (char *)v10;
    if ( !strcmp(v10, "1") )
    {
      j__unsetenv("PYINSTALLER_RESET_ENVIRONMENT");
      free(ptr);
      goto LABEL_9;
    }
    j__unsetenv("PYINSTALLER_RESET_ENVIRONMENT");
    free(ptr);
  }
```

After a quick search or asking of LLM, we get that pyinstaller is a way to make executables out of python code, which is known to be interpreted.

Kinda like a python compiler.

After a few searches or asking an LLM, we understand that we can extract the source code using a python package called `pyinstxtractor`, can be installed using `pip` or system-wide `apt` (for Debian-based Linux distributions).

## Extracting Python Package from binary

I installed it using `apt`, we then extract the stuff:
```bash
└─$ pyinstxtractor snakes
[+] Processing snakes
[+] Pyinstaller version: 2.1+
[+] Python version: 3.13
[+] Length of package: 8038990 bytes
[+] Found 30 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: snakes.pyc
[+] Found 112 files in PYZ archive
[+] Successfully extracted pyinstaller archive: snakes

You can now use a python decompiler on the pyc files within the extracted directory

└─$ ls -1 snakes_extracted
base_library.zip
libbz2.so.1.0
libcrypto.so.3
lib-dynload
libexpat.so.1
liblzma.so.5
libpython3.13.so.1.0
libz.so.1
libzstd.so.1
pyiboot01_bootstrap.pyc
pyimod01_archive.pyc
pyimod02_importers.pyc
pyimod03_ctypes.pyc
pyi_rth_inspect.pyc
PYZ.pyz
PYZ.pyz_extracted
snakes.pyc
struct.pyc
```

## Extracting Python Source code from extracted package
After a few searches into similar CTFs, or asking an LLM, we understand the source code is in `snakes.pyc`, as it generally follows the binary's name.

We extract it using [PyLingual](https://pylingual.io/), which is a popular Python Decompiler for .pyc files; We get the python source code, which we'll store in [snakes.reversed.py](./snakes.reversed.py).

We notice it is executing decoded base64 constant strings, we try decoding one on the fly to see what it is:
```python
└─$ python
Python 3.13.5 (main, Jun 25 2025, 18:55:22) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import base64
>>> base64.b64decode('aXNfY29ycmVjdCAmPSBub3QgKGJ1ZlsyXSAhPSAweDYzKQ==')
b'is_correct &= not (buf[2] != 0x63)'
```

Interesting, so it is doing manual checkup of `buf`, presumably the string we inputted. with static values, and `AND`ing the result with a checkup variable `is_correct`.

## Modifying the python script into printing us the flag

We tweak the source a bit using VSCode's features, to print all the base64 decoded lines, instead of executing them (we just replaced the `exec` with `print`), You'll find the script in [snakes.reversed.0.py](./snakes.reversed.0.py).

We get the results in plaintext:
```bash
└─$ python snakes.reversed.0.py
is_correct = True
buf = input("Enter the flag: ").encode()

if len(buf) != 34: print("Incorrect."); sys.exit(0)

is_correct &= not (buf[1] != ord('h'))
is_correct &= not (buf[3] != 116)
is_correct &= not (buf[4] != ord('f'))
is_correct &= not (buf[6] != ord('P'))
is_correct &= not (buf[2] != 0x63)
is_correct &= not (buf[12] != ord('_'))
is_correct &= not (buf[7] != ord('y'))
is_correct &= not (buf[8] != 116)
is_correct &= not (buf[9] != ord('h'))
is_correct &= not (buf[10] != ord('0'))
is_correct &= not (buf[11] != 110)
is_correct &= not (buf[18] != 53)
is_correct &= not (buf[13] != 0b1010010 or buf[5] != ord('{'))
is_correct &= not (buf[14] != ord('3'))
is_correct &= not (buf[15] != 0b1110110)
is_correct &= not (buf[16] != ord('3'))
is_correct &= not (buf[17] != 0o162)
is_correct &= not (buf[29] != 0o162)
is_correct &= not (buf[19] != ord('1'))
is_correct &= not (buf[20] != 0b1101110)
is_correct &= not (buf[22] != ord('_'))
is_correct &= not (buf[23] != 0x47)
is_correct &= not (buf[24] != ord('0'))
is_correct &= not (buf[33] != ord('}'))
is_correct &= not (buf[26] != ord('5'))
is_correct &= not (buf[21] != 0x67)
is_correct &= not (buf[28] != ord('B') or buf[27] != ord('_'))
is_correct &= not (buf[25] != ord('3'))
is_correct &= not (buf[30] != 0o162)
is_correct &= not (buf[0] != 0x67)
is_correct &= not (buf[32] != 0o162 or buf[31] != 0o162)

print('Correct.' * is_correct + 'Incorrect.' * (not is_correct))
```

We can now give it to an LLM or further fix it by assigning each condition to the buffer array, and make it print us the expected flag.

You'll find the final solve script in [snakes.reversed.1.py](./snakes.reversed.1.py), We execute it, and we find the flag:
```bash
└─$ python snakes.reversed.1.py
ghctf{Pyth0n_R3v3r51ng_G035_Brrrr}
```