#!/usr/bin/env python3

import re
import subprocess
import sys

BANNER = """
==============================
 ☠️ oh my Shell ☠️
==============================
"""

def main():
    print(BANNER, flush=True)

    while True:
        sys.stdout.write("# ")
        sys.stdout.flush()
        cmd = sys.stdin.readline()

        if not cmd:
            break  # CTRL+D or client disconnected

        cmd = cmd.strip()

        if cmd.lower() in ["exit", "quit"]:
            print("Bye!")
            break

        # Reject alphanumeric characters except "$" (since your shell is $$)
        if re.search(r'[a-mo-zA-Z0-9]', cmd):
            print("❌")
            continue

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                executable="/bin/zsh",  # 💥
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=3
            )
            output = result.stdout + result.stderr
            print(output.strip())
        except subprocess.TimeoutExpired:
            print("⏰ Command timed out.")
        except Exception as e:
            print(f"🔥 Error: {str(e)}")

if __name__ == "__main__":
    main()
