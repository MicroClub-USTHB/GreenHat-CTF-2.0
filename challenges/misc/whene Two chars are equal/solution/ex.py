import subprocess
import time

def measure_time(pin_guess, trials=5):
    durations = []
    for _ in range(trials):
        start = time.perf_counter()

        subprocess.run(
            ["./pin_checker"],
            input=pin_guess.encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        end = time.perf_counter()
        durations.append(end - start)
    return sum(durations) / trials

def guess_pin():
    known = ""
    print("[*] Starting timing attack...\n")
    for i in range(8):
        timings = {}
        print(f"[+] Guessing digit {i+1}/8...")

        for d in "0123456789":
            guess = known + d + "0" * (7 - i)  # pad with zeros
            avg_time = measure_time(guess)
            timings[d] = avg_time
            print(f"    Tried {guess} => Avg Time: {avg_time:.8f} sec")

        best_digit = max(timings, key=timings.get)
        known += best_digit
        print(f"[✓] Digit {i+1} guessed: {best_digit}")
        print(f"[→] PIN so far: {known}\n")

    print(f"[✔] Final PIN: {known}")
    return known

guess_pin()
