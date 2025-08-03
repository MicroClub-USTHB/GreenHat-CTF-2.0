# Checkmate — Writeup

**Category:** Misc  
**Difficulty:** Easy  
**Author:** 0k4r1n

---

## Challenge Description

> Maybe the moves are more than just strategy.

You're given a `.pgn` file containing strange chess games. The moves seem random — but there's a deeper message encoded in them.

---

## Recon & Research

After analyzing the PGN file, it becomes clear that the game is not about strategy — it's about **data hidden in the moves**.

A quick search for:
- chess encryption
- store data in chess
- file hidden in PGN

leads to:

-  [YouTube Video - Storing files in chess](https://www.youtube.com/watch?v=TUtafoC4-7k)
-  [GitHub Repo - chessencryption](https://github.com/WintrCat/chessencryption)

---

## Solution

Clone the repo:

```bash
git clone https://github.com/WintrCat/chessencryption
cd chessencryption
```
Use the provided decode function with the PGN:
```bash
from decode import decode

with open("crazy_game.pgn", "r") as f:
    pgn_data = f.read()

decode(pgn_data, "recovered_secret.bin")
```
Run the script and open the output:
```bash
strings recovered_secret.bin

Or:

cat recovered_secret.bin
```
And you'll find:

🏁 Flag

ghctf{ch3ckm4te_g00d_g4m3}