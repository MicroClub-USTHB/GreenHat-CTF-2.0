def gray_to_binary(gray):
    binary = gray[0]
    for i in range(1, len(gray)):
        binary += str(int(binary[i-1]) ^ int(gray[i]))
    return binary

def binary_to_gray(binary):
    binary = ''.join(binary.split())   
    gray = binary[0]
    for i in range(1, len(binary)):
      gray += str(int(binary[i - 1]) ^ int(binary[i]))
    return gray

binary = "01100111 01101000 01100011 01110100 01100110 01111011 01110100 01101000 00110100 01110100 01110011 01011111 01110111 01101000 01111001 01011111 01110011 01110100 01110010 01101101 01011111 01110100 01100110 00110001 01100100 00110011 01101011 01111101"
gray = binary_to_gray(binary)
print("Gray:", gray)

recovered_binary = gray_to_binary(gray)
print("Recovered Binary:", recovered_binary)

