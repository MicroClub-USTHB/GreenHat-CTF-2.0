# hash1 - crypto Challenge

🏴 **Challenge Name:** hash1

## 📝 Challenge Description

I hashed 3 more of my most secret passwords with SHA256. To make the passwords even more unbreakable, I mutated each one according to the following rules:

- **Password 1:** Append 3 characters at the end, in the following order: a special character, a number, and an uppercase letter
- **Password 2:** A typo was made when typing the password. Consider a typo to mean a single-character deletion from the password
- **Password 3:** Make the password leet (and since I'm nice, I'll tell you a hint: only vowels are leetified!)

I'm confident you'll never be able to crack my hashes now! Do your worst!

```
5e09f66ae5c6b2f4038eba26dc8e22d8aeb54f624d1d3ed96551e900dac7cf0d
fb58c041b0059e8424ff1f8d2771fca9ab0f5dcdd10c48e7a67a9467aa8ebfa8
4ac53d04443e6786752ac78e2dc86f60a629e4639edacc6a5937146f3eacc30f
```

Use the rockyou.txt wordlist.  
**Flag format:** ghctf{pass1_pass2_pass3}  
Rules are meant to be broken... Right ?!

## 🔧 Solution Overview

### Password 1 - Suffix Mutation Attack

**Target Hash:** `5e09f66ae5c6b2f4038eba26dc8e22d8aeb54f624d1d3ed96551e900dac7cf0d`

The first password follows the pattern of appending a special character, digit, and uppercase letter. This can be solved using custom John the Ripper rules:

```ini
[List.Rules:append_special_digit_uppercase]
Az"[!@#$%^&*]"Az"[0123456789]"Az"[ABCDEFGHIJKLMNOPQRSTUVWXYZ]"
```

**Command:**

```bash
john --wordlist=rockyou.txt --rules=append_special_digit_uppercase \
     --format=Raw-SHA256 hash1.txt
```

**Hashcat equivalent:**

```bash
hashcat -m 1400 -a 6 \
  5e09f66ae5c6b2f4038eba26dc8e22d8aeb54f624d1d3ed96551e900dac7cf0d \
  rockyou.txt "?s?d?u"
```

**Cracked Password:** `hyepsi^4B`

### Password 2 - Single Character Deletion

**Target Hash:** `fb58c041b0059e8424ff1f8d2771fca9ab0f5dcdd10c48e7a67a9467aa8ebfa8`

This simulates a common typo where one character is accidentally omitted. John's jumbo ruleset handles various typo patterns including deletions:

**Command:**

```bash
john --wordlist=rockyou.txt --rules=jumbo \
     --format=Raw-SHA256 hash2.txt
```

**Cracked Password:** `thecowsaysmo` (derived from `thecowsaysmoo` with the final 'o' deleted)

### Password 3 - Vowel Leetification

**Target Hash:** `4ac53d04443e6786752ac78e2dc86f60a629e4639edacc6a5937146f3eacc30f`

Only vowels are transformed using common leet substitutions (a→@, e→3, i→1, o→0). Custom rule:

```ini
[List.Rules:leet_vowels]
sa4 sa@ sb6 sc< sc{ se3 sg9 si1 si! so0 sq9 ss5 ss$ st7 st+ sx%
```

**Command:**

```bash
john --wordlist=rockyou.txt --rules=leet_vowels \
     --format=Raw-SHA256 hash3.txt
```

**Hashcat equivalent:**

```bash
hashcat -m 1400 -a 1 \
  4ac53d04443e6786752ac78e2dc86f60a629e4639edacc6a5937146f3eacc30f \
  rockyou.txt -r rules/leetspeak.rule
```

**Cracked Password:** `unf0rg1v@bl3`

## 🏁 Final Flag

**ghctf{hyepsi^4B_thecowsaysmo_unf0rg1v@bl3}**
