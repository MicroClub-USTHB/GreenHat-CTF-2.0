## STEP 1 : Bruteforce to crack archive password
transform challenge.rar into hash file using rar2john 
use john with the wordlist rockyou.txt to crash the password

## STEP 2 : fix corrupted files 
check the files's binary with hexedit: 
 for the png file : check the tags like PNG, IHDR .... (but dont waste your time it's a prank)
 for the pdf file: all the binaries is flipped so flip binaries again with a function 
  ```python
  def flip_file(input_path, output_path):
    with open(input_path, "rb") as f:
        data = f.read()
    flipped = data[::-1]
    with open(output_path, "wb") as f:
        f.write(flipped)
  ```
## STEP 3 : get the check.pdf password 
to get the password you have to read carefully the document, you'll notice some characters in unicode ascii, after assemble all the characters you'll have this password : ghctf read1ng_FB1_rep0rt$_1s_FuN 

# STEP 4 : get the flag
after having the password from the step3, enter it to the pdf password check, then you donna have the flag.


## hint: length of the password for the rar file 
  len(x)<10

   