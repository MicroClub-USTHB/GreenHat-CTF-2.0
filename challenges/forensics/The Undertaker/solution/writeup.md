- try to understand that the challenge uses the tomb tool or as some ppl call it the linux undertaker
- when u get that point, u will understand that the image hides the key that opens the .tomb file that hides the flag
- u need a password for that, u will find it in the metadata of the image
```bash
$ exiftool img.jpeg 
Comment                         : dGhlIHBhc3N3b3JkIGlzOiBQYSQkdzByRDQzMjE=
```
- base64 text that translate to 'the password is: Pa$$w0rD4321'
- now u can get the key by exhume it from the image
```bash
$ tomb exhume img.jpeg -k key.key -f
``` 
- u must give it .key extension 
- now use the key to open the grave aka the file.tomb 
```bash 
$ tomb open -k key.key file.tomb -f
```
- u will see that the file is opend in /media/file
- u will find a flag.txt there

```bash
$ cat flag.txt    
ghctf{T0mB_1s_Th3_Und3rT4k3r}
```

- close the tomb 
```bash
$ tomb close 
```
