# The Goat Challenge Write-up

## Description

Who is the greatest footballer of all time? Encrypted Flag: `}WLCMNCUHIWLCMNCUHIWLCMNCUHIWLQK{ybcuu`

## Challenge Overview

I created this multi-layered cryptographic challenge that combines:

1. **Social Engineering/Knowledge**: Understanding the hint about "the greatest footballer"
2. **Vigenère Cipher**: Classical polyalphabetic substitution cipher
3. **Mirror Cipher**: Simple reversal transformation

The challenge I designed requires recognizing the football reference, deducing the key, and applying two decryption steps in the correct order.

## Given Information

- **Encrypted Text:** `}WLCMNCUHIWLCMNCUHIWLCMNCUHIWLQK{ybcuu`
- **Hint:** "Who is the greatest footballer of all time?"
- **Context:** The challenge title "The Goat" (Greatest Of All Time)

## Solution Approach

### Step 1: Analyze the Hint

The hint "Who is the greatest footballer of all time?" combined with the title "The Goat" (GOAT = Greatest Of All Time) suggests we need to identify a famous footballer. Given the context and common debates, this likely refers to **Cristiano Ronaldo** or **Lionel Messi**.

### Step 2: Pattern Recognition

Looking at the encrypted text structure:

- It appears to be a flag format (starts with `}` and ends with `{`, suggesting reversal)
- Length suggests it might be a standard flag format when decrypted
- The pattern suggests multiple encryption layers

### Step 3: Key Deduction

Since the hint points to the greatest footballer, and considering popular culture references:

- **"cristiano"** (referring to Cristiano Ronaldo) is a likely key
- His famous celebration "SIUUU" is also culturally relevant
- The length and pattern of the key should match the cipher requirements

### Step 4: Identify Encryption Methods

Based on the encrypted text characteristics:

1. **Vigenère Cipher**: The repeating patterns suggest a polyalphabetic cipher
2. **Mirror/Reversal Cipher**: The reversed flag format (ending with `{` instead of starting) suggests reversal

## Solution Implementation

```python
def vigenere_decrypt(ciphertext, key):
    """
    Decrypt Vigenère cipher using the provided key
    """
    plaintext = ''
    key = key.lower()
    key_len = len(key)
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            # Calculate the shift value from the key
            shift = ord(key[key_index % key_len]) - ord('a')

            # Decrypt based on case
            if char.islower():
                decrypted = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                decrypted = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))

            plaintext += decrypted
            key_index += 1
        else:
            # Non-alphabetic characters remain unchanged
            plaintext += char

    return plaintext

def mirror_cipher(text):
    """
    Apply mirror cipher (simple reversal)
    """
    return text[::-1]

# Given encrypted text
encrypted = "}WLCMNCUHIWLCMNCUHIWLQK{ybcuu"

# Step 1: Vigenère decryption with "cristiano" as key
key = "cristiano"
decrypted_vigenere = vigenere_decrypt(encrypted, key)
print(f"[+] After Vigenère decryption: {decrypted_vigenere}")

# Step 2: Apply mirror cipher (reversal)
final_flag = mirror_cipher(decrypted_vigenere)
print(f"[+] Final flag: {final_flag}")
```

## Step-by-Step Decryption

### Step 1: Vigenère Decryption

Using the key **"cristiano"**:

```
Encrypted: }WLCMNCUHIWLCMNCUHIWLCMNCUHIWLQK{ybcuu
Key:        cristiano cristiano cristiano cristiano
Result:     }UUUUUUUUUUUUUUUUUUUUUUUUUUUUUIS{ftchg
```

### Step 2: Mirror Cipher (Reversal)

Reverse the decrypted string:

```
Reversed:  }UUUUUUUUUUUUUUUUUUUUUUUUUUUUUIS{ftchg
Final:    ghctf{SIUUUUUUUUUUUUUUUUUUUUUUUUUUUUU}
```
