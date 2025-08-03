from binascii import unhexlify
import struct

def decrypt(encrypted_hex, key):
    encrypted_bytes = unhexlify(encrypted_hex)
    decrypted = b''

    for i in range(0, len(encrypted_bytes), 4):
        block = encrypted_bytes[i:i+4]
        if len(block) < 4:
            block = block.ljust(4, b'\x00')  # pad short final block if needed
        encrypted_int = struct.unpack('<I', block)[0]
        decrypted_int = encrypted_int ^ key
        decrypted += struct.pack('<I', decrypted_int)

    return decrypted.rstrip(b'\x00')

def is_printable(data):
    """Check if all bytes are printable ASCII"""
    return all(32 <= b <= 126 or b in (10, 13) for b in data)

def brute_force(encrypted_hex):
    for key in range(0xFF_FF_FF_FF + 1):
        decrypted = decrypt(encrypted_hex, key)
        if is_printable(decrypted):
            try:
                decrypted_str = decrypted.decode()
                if 'ghctf{' in decrypted_str.lower():
                    print(f"[+] Key Found: 0x{key:08X} --> {decrypted_str}")
                    break  # comment this if you want all possible matches
            except UnicodeDecodeError:
                continue
        if key % 1_000_000 == 0:
            print(f"[+] Passed {key} tries, {0xFF_FF_FF_FF - key} left.")

with open("../assets/flag.txt.enc", "r") as f:
    encrypted_hex = f.read().strip()

print(f"[*] Starting brute-force on ciphertext: {encrypted_hex}")
brute_force(encrypted_hex)

# └─$ gcc challenge/src/Unbreakable.c -o assets/Unbreakable && echo -n "ghctf{Ungu3ss4ble_but_Br34k4b1e}" | ./assets/Unbreakable
# Enter what you want to encrypt: Using key: 0x02397878
# Encrypted output (hex): 1F105A761E036C6C1F0D0A710B4C5B6E1D275B770C277B704B4C52361A495C7F

