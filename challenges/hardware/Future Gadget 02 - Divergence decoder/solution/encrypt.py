def binary_to_arduino_led_file(input_file, output_file, led_pin=13, delay_time=100):
    with open(input_file, 'r') as f:
        binary_data = f.read().replace('\n', '').replace(' ', '')

    if len(binary_data) % 8 != 0:
        print("Warning: Binary length is not a multiple of 8 bits.")

    code = []
    code.append(f"int ledPin = {led_pin};")
    code.append("void setup() {")
    code.append("  pinMode(ledPin, OUTPUT);")
    code.append("}")
    code.append("")
    code.append("void loop() {")

    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        if len(byte) < 8:
            continue  # skip incomplete bytes
        try:
            ascii_char = chr(int(byte, 2))
        except ValueError:
            ascii_char = '?'

        # Add comment with ASCII character
        code.append(f"  // '{ascii_char}' => {byte}")
        for bit in byte:
            if bit == '0':
                code.append(f"  digitalWrite(ledPin, LOW);")
            elif bit == '1':
                code.append(f"  digitalWrite(ledPin, HIGH);")
            code.append(f"  delay({delay_time});")

    code.append("}")

    with open(output_file, 'w') as f:
        f.write('\n'.join(code))

    print(f"Arduino code written to: {output_file}")

# Example usage
binary_to_arduino_led_file('binary.txt', 'led_output.ino')
