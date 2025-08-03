def decrypt_link_id():
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    key = [16, 4, 20, 8]
    cipherText = "ht0ikBf4BPieIKcacAROs7gQ0eX_5TUNTcBrQWqArJNE"
    plainText = []
    key_index = 0
    alphabet_len = len(alphabet)
    key_len = len(key)

    for ch in cipherText:
        if ch in alphabet:
            cipher_index = alphabet.index(ch)
            shift = key[key_index % key_len]
            plain_index = (cipher_index - shift) % alphabet_len
            plainText.append(alphabet[plain_index])
            key_index += 1
        else:
            plainText.append(ch)

    print("".join(plainText))

decrypt_link_id()
