buf = bytearray(34)

buf[1] = ord('h')
buf[3] = 116
buf[4] = ord('f')
buf[6] = ord('P')
buf[2] = 0x63
buf[12] = ord('_')
buf[7] = ord('y')
buf[8] = 116
buf[9] = ord('h')
buf[10] = ord('0')
buf[11] = 110
buf[18] = 53
buf[13] = 0b1010010
buf[5] = ord('{')
buf[14] = ord('3')
buf[15] = 0b1110110
buf[16] = ord('3')
buf[17] = 0o162
buf[29] = 0o162
buf[19] = ord('1')
buf[20] = 0b1101110
buf[22] = ord('_')
buf[23] = 0x47
buf[24] = ord('0')
buf[33] = ord('}')
buf[26] = ord('5')
buf[21] = 0x67
buf[28] = ord('B')
buf[27] = ord('_')
buf[25] = ord('3')
buf[30] = 0o162
buf[0] = 0x67
buf[32] = 0o162
buf[31] = 0o162

print(buf.decode())