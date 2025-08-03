import base64

src = \
"""is_correct = True
buf = input("Enter the flag: ").encode()

if len(buf) != 34: print("Incorrect."); sys.exit(0)

is_correct &= not (buf[1] != ord('h'))
is_correct &= not (buf[3] != 116)
is_correct &= not (buf[4] != ord('f'))
is_correct &= not (buf[6] != ord('P'))
is_correct &= not (buf[2] != 0x63)
is_correct &= not (buf[12] != ord('_'))
is_correct &= not (buf[7] != ord('y'))
is_correct &= not (buf[8] != 116)
is_correct &= not (buf[9] != ord('h'))
is_correct &= not (buf[10] != ord('0'))
is_correct &= not (buf[11] != 110)
is_correct &= not (buf[18] != 53)
is_correct &= not (buf[13] != 0b1010010 or buf[5] != ord('{'))
is_correct &= not (buf[14] != ord('3'))
is_correct &= not (buf[15] != 0b1110110)
is_correct &= not (buf[16] != ord('3'))
is_correct &= not (buf[17] != 0o162)
is_correct &= not (buf[29] != 0o162)
is_correct &= not (buf[19] != ord('1'))
is_correct &= not (buf[20] != 0b1101110)
is_correct &= not (buf[22] != ord('_'))
is_correct &= not (buf[23] != 0x47)
is_correct &= not (buf[24] != ord('0'))
is_correct &= not (buf[33] != ord('}'))
is_correct &= not (buf[26] != ord('5'))
is_correct &= not (buf[21] != 0x67)
is_correct &= not (buf[28] != ord('B') or buf[27] != ord('_'))
is_correct &= not (buf[25] != ord('3'))
is_correct &= not (buf[30] != 0o162)
is_correct &= not (buf[0] != 0x67)
is_correct &= not (buf[32] != 0o162 or buf[31] != 0o162)

print('Correct.' * is_correct + 'Incorrect.' * (not is_correct))"""

with open("snakes.py", "w") as dst:
    dst.write("import base64\n")
    dst.write("import sys\n")

    for line in src.splitlines():
        encoded = base64.b64encode(line.encode()).decode()
        dst.write(f"exec(base64.b64decode('{encoded}'))\n")