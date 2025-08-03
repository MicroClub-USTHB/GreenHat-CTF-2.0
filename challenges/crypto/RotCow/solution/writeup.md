# RotCow - Write-up

## Challenge Analysis

We are given a text file containing what appears to be encrypted text:

```
BBBZbBZbBZbBZbBZbBZbBZbBZbBZZZzbBZZZZZZzbBZZZZBBZBbzBbZbBzbBzbbzBb
ZZZzbBZZZZZZzbBZZZZBBZBbzBbZbBzbBzbbzBbZZZzbBZZZZZZzbBZZZZBBZBbzBb
ZbBzbBzbbBBBzbBBBBzBbzBbZZZzbBZZZZBBZBbzbBZbBzBbzbbzBbzBbZZZzbBzbB
...
```

The text consists of only a few characters: `B`, `Z`, `b`, and `z`. The challenge title "RotCow" gives us a hint about the encryption method used.

## Solution Approach

The title suggests a combination of:

1. **ROT** - Rotation cipher (like ROT13)
2. **Cow** - Moo cipher (a substitution cipher using "moo" sounds)

Let's analyze this step by step:

### Step 1: Identify the Pattern

Looking at the encrypted text, we can see it uses only 4 characters: `B`, `Z`, `b`, `z`.

### Step 2: Understanding Moo Cipher

The Moo cipher is a substitution cipher where:

- Text is first converted to binary
- Binary digits are then replaced with "moo" sounds:
  - `0` → `moo` (lowercase)
  - `1` → `MOO` (uppercase)
- Or in some variations, different combinations of `M`, `o`, `O` are used

However, in our case, we have `B`, `Z`, `b`, `z` instead of `M`, `o`, `O`.

### Step 3: Decryption Process

Using CyberChef (https://gchq.github.io/CyberChef/), we can attempt to decode this:

1. First, we need to apply a **ROT13** transformation to convert the characters back to the standard Moo cipher format
2. Then decode using the **Moo cipher**

### Step 4: Using CyberChef

1. **Input:** Paste the encrypted text into CyberChef
2. **Apply ROT13:** Add the "ROT13" operation
   - This converts: `B` → `O`, `Z` → `M`, `b` → `o`, `z` → `m`
3. **Result after ROT13:** The text becomes standard Moo cipher format with `M`, `O`, `o`, `m`
4. **Decode Moo:** The text now contains patterns of `moo`, `MOO`, `Moo`, etc.

### Step 5: Alternative Tool - Mystery Toolbox

We can also use the Geocaching Mystery Toolbox (https://mysterytoolbox.organisingchaos.com/Ciphers/cipher/Moo):

1. After applying ROT13 to get the standard Moo format
2. Use the Moo cipher decoder
3. Click "Decrypt" to get the final result

## Final Solution

After applying ROT13 followed by Moo cipher decryption, we get:

**Flag:** `ghctf{Wh3n_C0w5_3nc0d3_Y0ur_M3ss4g3_Y0u_N33d_4_M00_D3crypt0r}`

## Tools Used

1. **CyberChef** (https://gchq.github.io/CyberChef/) - For ROT13 and general text manipulation
2. **Geocaching Mystery Toolbox** (https://mysterytoolbox.organisingchaos.com/) - For Moo cipher decryption
