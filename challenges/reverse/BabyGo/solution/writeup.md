We inspect the binary we got:

```bash
└─$ file BabyGo
BabyGo: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=b99a2af8b16fd3a229ba7de67a7f8cece3b5825a, with debug_info, not stripped
```

Once we run `strings` on the binary, we notice some weird patterns and names that aren't native to C programs, once we look closely or send output to LLM, we conclude it's a ***GO*** Binary (hence the challenge's name `BabyGo`).

We immedately open the binary in IDA, as Ghidra sucks with GO binaries, and we get the following `main_main()` function:
```C
// main.main
// local variable allocation has failed, the output may be wrong!
void __golang main_main(){
  bufio_Reader_0 *v0; // rcx
  internal_abi_ITab *v1; // rdi OVERLAPPED
  error_0 v2; // rsi
  __int128 v3; // xmm15
  _slice_interface_ *p_a; // rax OVERLAPPED
  __int64 v5; // rdx
  _QWORD *v6; // r11
  __int64 v7; // rbx
  __int64 v8; // rcx
  int v9; // rcx
  bool v10; // cl
  error_0 v11; // rsi
  _slice_interface_ *v12; // rax OVERLAPPED
  __int64 v13; // rdx
  _QWORD *v14; // r11
  __int64 v15; // rbx
  __int64 v16; // rcx
  _slice_interface_ *v17; // rax OVERLAPPED
  __int64 v18; // rdx
  _QWORD *v19; // r11
  __int64 v20; // rbx
  __int64 v21; // rcx
  bufio_Reader_0 *b; // [rsp+2h] [rbp-D0h]
  _slice_interface_ a; // [rsp+5Ah] [rbp-78h] BYREF
  internal_abi_ITab *v24; // [rsp+72h] [rbp-60h]
  string_0 s; // [rsp+7Ah] [rbp-58h]
  _slice_interface_ *v26; // [rsp+8Ah] [rbp-48h]
  _slice_interface_ *v27; // [rsp+92h] [rbp-40h]
  __int64 v28; // [rsp+9Ah] [rbp-38h]
  __int64 v29; // [rsp+A2h] [rbp-30h]
  _slice_interface_ *v30; // [rsp+AAh] [rbp-28h]
  _slice_interface_ *v31; // [rsp+B2h] [rbp-20h]
  __int64 v32; // [rsp+BAh] [rbp-18h]
  __int64 v33; // [rsp+C2h] [rbp-10h]
  io_Reader_0 v34; // 0:rax.8,8:rbx.8
  string_0 v35; // 0:rax.8,8:rbx.8

  v34.data = os_Stdin;
  v34.tab = (internal_abi_ITab *)&go_itab__ptr_os_File_comma_io_Reader;
  bufio_NewReader(v34, v0);
  b = (bufio_Reader_0 *)v34.tab;
  a.len = *((_QWORD *)&v3 + 1);
  p_a = &a;
  a.array = (interface__0 *)&RTYPE_string;
  if ( *(_DWORD *)&runtime_writeBarrier.enabled )
  {
    runtime_gcWriteBarrier1();
    *v6 = v5;
  }
  p_a->len = (int)&off_4EA520;
  v7 = 1LL;
  v8 = 1LL;
  fmt_Print(*(_slice_interface_ *)&p_a, (int)v1, v2);
  v35.len = 10LL;
  bufio__ptr_Reader_ReadString(b, 0xAu, *(string_0 *)(&v1 - 1), v2);
  s.str = v35.str;
  s.len = 10LL;
  v11.tab = v1;
  a.cap = v9;
  v24 = v1;
  strings_TrimSpace(v35, *(string_0 *)(&v1 - 1));
  main_checkInput(v35, v10);
  if ( LOBYTE(v35.str) )
  {
    a.len = *((_QWORD *)&v3 + 1);
    v12 = &a;
    v30 = &a;
    a.array = (interface__0 *)&RTYPE_string;
    if ( *(_DWORD *)&runtime_writeBarrier.enabled )
    {
      runtime_gcWriteBarrier1();
      *v14 = v13;
    }
    v12->len = (int)&off_4EA530;
    v31 = v12;
    v32 = 1LL;
    v33 = 1LL;
    v15 = 1LL;
    v16 = 1LL;
    fmt_Println(*(_slice_interface_ *)&v12, (int)v1, v11);
  }
  else
  {
    a.len = *((_QWORD *)&v3 + 1);
    v17 = &a;
    v26 = &a;
    a.array = (interface__0 *)&RTYPE_string;
    if ( *(_DWORD *)&runtime_writeBarrier.enabled )
    {
      runtime_gcWriteBarrier1();
      *v19 = v18;
    }
    v17->len = (int)&off_4EA540;
    v27 = v17;
    v28 = 1LL;
    v29 = 1LL;
    v20 = 1LL;
    v21 = 1LL;
    fmt_Println(*(_slice_interface_ *)&v17, (int)v1, v11);
  }
}
```

After running it through an LLM and dynamically analyzing it, we understand it's reading our input and checking that input in the `main_checkInput()` function, which decides if it is correct or no.

We go and check the `main_checkInput()` function:
```c
// main.checkInput
void __golang main_checkInput(string_0 input, bool _r0)
{
  int v2; // rsi
  unsigned int str; // [rsp+34h] [rbp-164h]
  _QWORD r[34]; // [rsp+40h] [rbp-158h] BYREF
  unsigned __int64 v5; // [rsp+150h] [rbp-48h]
  int k; // [rsp+158h] [rbp-40h]
  _QWORD *v7; // [rsp+160h] [rbp-38h]
  unsigned __int64 v8; // [rsp+168h] [rbp-30h]
  __int64 v9; // [rsp+170h] [rbp-28h]
  _QWORD *v10; // [rsp+178h] [rbp-20h]
  string_0 s; // [rsp+180h] [rbp-18h]
  uint8 *inputa; // [rsp+1A0h] [rbp+8h]
  string_0 v13; // 0:rax.8,8:rbx.8

  inputa = input.str;
  ((void (__fastcall *)(_QWORD *))loc_477014)(r);
  v10 = r;
  r[0] = 173LL;
  r[1] = 162LL;
  r[2] = 169LL;
  r[3] = 190LL;
  r[4] = 172LL;
  r[5] = 177LL;
  r[6] = 147LL;
  r[7] = 249LL;
  r[8] = 255LL;
  r[9] = 149LL;
  r[10] = 159LL;
  r[11] = 184LL;
  r[12] = 149LL;
  r[13] = 152LL;
  r[14] = 249LL;
  r[15] = 254LL;
  r[16] = 174LL;
  r[17] = 179LL;
  r[18] = 149LL;
  r[19] = 158LL;
  r[20] = 250LL;
  r[21] = 149LL;
  r[22] = 141LL;
  r[23] = 250LL;
  r[24] = 149LL;
  r[25] = 172LL;
  r[26] = 169LL;
  r[27] = 175LL;
  r[28] = 254LL;
  r[29] = 255LL;
  r[30] = 174LL;
  r[31] = 183LL;
  v7 = r;
  v8 = 32LL;
  v9 = 32LL;
  r[33] = input.len;
  r[32] = 32LL;
  if ( input.len == 32 )
  {
    v2 = 32LL;
    s.str = inputa;
    s.len = 32LL;
    k = 0LL;
    do
    {
      if ( s.len <= k )
        break;
      v5 = k;
      str = s.str[k];
      if ( str >= 0x80 )
      {
        v13 = s;
        runtime_decoderune(s, k, (int32)r, v2);
        str = (unsigned int)v13.str;
        k = v13.len;
      }
      else
      {
        ++k;
      }
      if ( v8 <= v5 )
        runtime_panicIndex();
      v2 = (int)&v7[v5];
    }
    while ( *(_QWORD *)v2 == ((int)str ^ 0xCALL) );
  }
}
```

We notice it is doing a XOR with `0xCA`, and verifying if it matches variable `r`, foreach character, so we simply XOR the result array with `0xCA` to get the flag, solve is in `/solution/solve.py` 