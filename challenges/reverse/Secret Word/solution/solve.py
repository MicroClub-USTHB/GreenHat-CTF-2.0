from pwn import *
import struct

HOST = 'ghctf.microclub.info'
PORT = 13800

def get_chcksum(cur_id: int, data: bytes, key: bytes):
    result = cur_id
    for index, byte in enumerate(data):
        result += data[index] ^ key

    return result

def xor_bytes(data: bytes, key: bytes):
    result = b''
    for index, byte in enumerate(data):
        result += bytes([data[index] ^ key])

    return result

PaYLOAD_SIZE = 32

ID = 0x00_00_00_00
data_key = 0x00
checksum_key = 0x00
service_code = 0xFF
SECRET_WORD = b'flag'

payload = b''
payload += SECRET_WORD
payload += b'\x00' * (PaYLOAD_SIZE - len(payload))
encrypted_payload = xor_bytes(payload, data_key)

packet = b''
packet += struct.pack('<I', ID)             # ID
packet += struct.pack('<B', data_key)       # data_key
packet += struct.pack('<B', checksum_key)   # checksum_key
packet += struct.pack('<B', service_code)   # service_code
packet += encrypted_payload                 # payload
packet += struct.pack('<Q', get_chcksum(ID, payload, checksum_key)) # checksum

print(f"Sending packet of length {len(packet)}:")
print(''.join([f"\\x{b:02X}" for b in packet]))

p = remote(HOST, PORT, ssl=True)
p.sendline(packet)

p.interactive()