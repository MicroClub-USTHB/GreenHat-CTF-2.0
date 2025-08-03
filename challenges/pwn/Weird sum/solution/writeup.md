## Vulnerability Explanation

The challenge reads two 16-bit signed integers **a** and **b**, checks they’re non-negative, then computes:

```c
short sum = a + b;
if (sum == target) flag();
```

Because sum is a signed 16-bit value, it wraps modulo 2¹⁶. You can choose large non-negative **a** and **b** so that their addition overflows into the desired negative target.

## Exploitation Steps

Read the target: the binary prints out a random negative target (e.g. -42).
Set MAX_SHORT = 32767 (the largest 16-bit signed value).

Choose **a** = MAX_SHORT
Compute **b** = MAX_SHORT + target + 2:

b = MAX_SHORT + target + 2 # wraps to correct unsigned 16-bit

Send **a** and **b**. Even though both are non-negative and ≤ 32767, their signed 16-bit sum overflows to target, passing the check and calling flag().

### Flag : ghctf{1nt3ger_0v3rfl0w_m3rcyyyyyy}
