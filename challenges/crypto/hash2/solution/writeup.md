# hash2 - crypto Challenge

🏴 **Challenge Name:** hash2

## 📝 Challenge Description

If you thought rules were easy after the last challenge, think again! I've concocted more devious password mangling rules to push the limits of your cracking knowledge (and possibly your CPU...):

- **Password 1:** Prepend 1 uppercase letter, Swap the first 2 characters, Rotate it to the right 3 times, Append a 4-digit year since 1900.
- **Password 2:** Lowercase the entire password. Apply a random caesar cipher shift to all the letters in the password. Then, replace each alphanumeric character with its right neighbor on the QWERTY keyboard. Finally, reverse it.
- **Password 3:** Split the password in half, toggle the case of every consonant in the first half, randomly toggle the case of all vowels in the second half, then interleave the halves together. Assume password has an even length and is no more than 14 characters.

```
2a07038481b64a934495e5a91d011ecbf278aba8c5263841e1d13f73975d5397
cd6e58d947e2f7ace23cb6d602daa1ae46934c3c1f4800bfd25e6af2b555f6f5
84b9e0298b1beb5236b7fcd2dd67e67abf62d16fe6d591024178790238cb4453
```

Use the rockyou.txt wordlist.  
**Flag format:** ghctf{pass1_pass2_pass3}

## 🔧 Solution Overview

### Password 1 - Multi-Stage Rule Transformation

**Target Hash:** `2a07038481b64a934495e5a91d011ecbf278aba8c5263841e1d13f73975d5397`

This password involves a complex sequence: prepend uppercase letter → swap first 2 chars → rotate right 3 times → append year.

**John the Ripper Custom Rule:**

```ini
[List.Rules:custom_challenge1]
^[A-Z]X010D2}}}
```

Rule breakdown:

- `^[A-Z]` - Prepend uppercase letter
- `X010D2` - Extract char at pos 0, insert at pos 1, delete pos 0, then delete pos 2 (swaps first 2 chars)
- `}}}` - Rotate right 3 times

**Commands:**

```bash
# Generate transformed wordlist
john -w=rockyou.txt --rules=custom_challenge1 --stdout > rockyou2.txt

# Use hybrid mode to append 4-digit year
hashcat -m 1400 -a 6 "2a07038481b64a934495e5a91d011ecbf278aba8c5263841e1d13f73975d5397" rockyou2.txt "19?d?d"
```

**Cracked Password:** `er!bLigbroth1984`

### Password 2 - Complex Multi-Transformation Attack

**Target Hash:** `cd6e58d947e2f7ace23cb6d602daa1ae46934c3c1f4800bfd25e6af2b555f6f5`

This requires: lowercase → caesar shift → QWERTY right-shift → reverse. Too complex for standard rules, requiring custom scripting.

**Step 1 - Lowercase transformation:**

```ini
[List.Rules:custom_challenge2]
l
```

```bash
john -w=rockyou.txt --rules=custom_challenge2 --stdout > rockyou_min.txt
```

**Step 2 - Caesar shifts (ROT1-ROT25) with QWERTY mapping:**

Custom C script for ROT transformations:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void caesar_shift_lower(const char *input, char *output, int shift) {
    int i = 0;
    while (input[i] != '\0' && i < MAX_LINE - 1) {
        char c = input[i];
        if (c >= 'a' && c <= 'z') {
            output[i] = 'a' + ((c - 'a' + shift) % 26);
        } else {
            output[i] = c;
        }
        i++;
    }
    output[i] = '\0';
}
```

QWERTY right-shift mapping header:

```c
char qwerty_right(char c) {
    switch (c) {
        case 'q': return 'w';
        case 'w': return 'e';
        // ... complete QWERTY mapping
        default: return c;
    }
}
```

**Step 3 - Apply reverse transformation:**

```bash
john -w=rot_output.txt --rules=r <hash_file> --format=raw-sha256
```

**Cracked Password:** `o4d@lkny@d`

### Password 3 - Complex Interleaving Algorithm

**Target Hash:** `84b9e0298b1beb5236b7fcd2dd67e67abf62d16fe6d591024178790238cb4453`

The most complex transformation: split in half → toggle consonants (first half) → toggle vowels with all combinations (second half) → interleave.

**Custom C Script for Complete Transformation:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

const char *VOWELS = "aeiouyAEIOUY";

int is_vowel(char c) {
    return strchr(VOWELS, c) != NULL;
}

char toggle_consonant(char c) {
    if (!isalpha(c) || is_vowel(c)) return c;
    return isupper(c) ? tolower(c) : toupper(c);
}

void generate_variants(const char *first, const char *second, FILE *out) {
    int len = strlen(first);
    int vowel_indices[MAX_VOWELS];
    int vowel_count = 0;

    // Find vowel positions in second half
    for (int i = 0; i < len; i++) {
        if (is_vowel(second[i])) {
            vowel_indices[vowel_count++] = i;
        }
    }

    // Generate all 2^n combinations
    int total = 1 << vowel_count;
    for (int mask = 0; mask < total; mask++) {
        char variant[8];
        strcpy(variant, second);

        // Apply vowel case toggles based on mask
        for (int i = 0; i < vowel_count; i++) {
            int index = vowel_indices[i];
            if ((mask >> i) & 1)
                variant[index] = toupper(second[index]);
            else
                variant[index] = tolower(second[index]);
        }

        // Interleave the halves
        char result[15];
        for (int i = 0, j = 0; i < len; i++) {
            result[j++] = first[i];
            result[j++] = variant[i];
        }
        result[2 * len] = '\0';
        fprintf(out, "%s\n", result);
    }
}
```

**Commands:**

```bash
gcc -O2 -o part3 part3.c
./part3 rockyou.txt
john -w=transformed_variants.txt <hash_file> --format=raw-sha256
```

**Cracked Password:** `CcoATnTdoyNY`

## 🏁 Final Flag

**ghctf{er!bLigbroth1984_o4d@lkny@d_CcoATnTdoyNY}**
