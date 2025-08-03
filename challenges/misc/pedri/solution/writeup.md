# Writeup: Pedri

### 1. Find the Key

The key is hidden in the hint. Calculate the difference between the ciphertext and plaintext character positions in the alphabet (`a-z, A-Z, 0-9`).

**Example (First Character):**
*   Ciphertext: `U` (position 46)
*   Plaintext: `E` (position 30)
*   Shift = (46 - 30) = **16**

Repeating this reveals the 4-digit key: `[16, 4, 20, 8]`

### 2. Decrypt the Link

Use the key to decrypt the ID from the broken link.

**Example (First Character of ID):**
*   Ciphertext ID starts with: `h` (position 7)
*   First key value: `16`
*   Plaintext Position = (7 - 16 + 62) % 62 = 53
*   Character at position 53 is `1`.

### 3. Get the Flag

Decrypting the full ID gives you the working link:

**`https://docs.google.com/document/d/1pGa4xVWlLY6sGS2WwxGc3WIKaD_XDQtLWx7IGmgjtJk/edit`**