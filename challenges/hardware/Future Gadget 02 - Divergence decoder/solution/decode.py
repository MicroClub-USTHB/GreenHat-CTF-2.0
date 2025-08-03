
binary=""
with open("led_output.ino", "r") as file:
    for line in file:
       if "HIGH" in line:
          binary+="1"
       elif "LOW" in line:
          binary+="0"
print ("Binary: " , binary)
flag =""
for i in range(0, len(binary), 8):
    byte = binary[i:i+8]
    flag += chr(int(byte, 2))

print("Flag : ", flag)