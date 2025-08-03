# main.py
import sys

def main():
    sys.stdout.write("Please enter your 8-digit PIN code:\n")
    sys.stdout.flush()
    pin = sys.stdin.readline().strip()
    if pin == "48390513":
        print("ghctf{5ide_ch4nn3l_4tt4ck}")
    else:
        print("Access denied.")
        sys.exit(1)

if __name__ == "__main__":
    main()
