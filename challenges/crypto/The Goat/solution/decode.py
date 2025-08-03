def vigenere_decrypt(ciphertext, key):
    plaintext = ''
    key = key.lower()
    key_len = len(key)
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % key_len]) - ord('a')
            if char.islower():
                decrypted = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                decrypted = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            plaintext += decrypted
            key_index += 1
        else:
            plaintext += char  

    return plaintext

def mirror_cipher(text):
    return text[::-1]

encrypted = "}WLCMNCUHIWLCMNCUHIWLCMNCUHIWLQK{ybcuu"  

# Étape 1 : déchiffrement Vigenère
key = "cristiano"
decrypted_mirror = vigenere_decrypt(encrypted, key)
print("[+] After Vigenère decryption:", decrypted_mirror)

# Étape 2 : Mirror Cipher
flag = mirror_cipher(decrypted_mirror)
print("[+] Final flag:", flag)