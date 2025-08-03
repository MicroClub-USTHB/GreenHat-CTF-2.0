encoded = b'ghctf{p5qd85yq9c1h4_kh1r3}'
decoded = bytearray()
# 0-5: as-is
decoded += encoded[0:6]
# 6-14: subtract 5
decoded += bytes([b - 5 for b in encoded[6:15]])
# 15: add 3
decoded.append(encoded[15] + 3)
# 16-25: as-is
decoded += encoded[16:26]
print(decoded.decode())