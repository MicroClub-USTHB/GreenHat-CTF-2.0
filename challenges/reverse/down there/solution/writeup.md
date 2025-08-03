- reverse the ELF 
- read the code after reversing 
- understand it 
- when u understand it, u will know that the flag was injected in a position in the image 
- get the flag by using some technics like `tail -c 26 kol3otla.png`
- why 26 ? cuz a 26 bytes flag was appended to the img duuh.
- the image is not complicated, u can extract the flag with `strings` command 
- still u will have to understand the ELF to fix some parts of the flag 

the flag is `ghctf{k0l_30tl4f1h4_kh1r3}`