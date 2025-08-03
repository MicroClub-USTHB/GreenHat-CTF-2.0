## Stego Challenge (Messi Edition)

A meme image hides the flag inside it.

Use stegseek with the popular rockyou.txt wordlist to crack the password and extract flag.txt:

```sh
stegseek --crack Que-miras-bobo.jpeg /usr/share/wordlists/rockyou.txt
```
