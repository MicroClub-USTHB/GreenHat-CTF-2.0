After getting the binary, we try `strings` on it as a reconnaissance step:
```bash
└─$ strings BabyRev              
CP/lib64/ld-linux-x86-64.so.2
puts
__libc_start_main
...
Not all information are printed, some are kept behind ;)
;*3$"
ghctf{H1dd3n_1n_pl41n_51ght}
Don't expect other challenges to be as easy as this xD
GCC: (Debian 14.2.0-19) 14.2.0
...
```

And Voila!, we get our flag: `ghctf{H1dd3n_1n_pl41n_51ght}`

And a funny little threat under it: `Don't expect other challenges to be as easy as this xD`