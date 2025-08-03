# secret^2 - Crypto Challenge

🏴 **Challenge Name:** secret^2

## 📝 Challenge Description

A cryptographic puzzle involving modular arithmetic and rational reconstruction. Can you recover the secret from its squared form?

**Given file:** `challenge.sage`

```python
from Crypto.Util.number import bytes_to_long as b2l

secret_1 = Integer(b2l(b'<Redacted 1>'))
secret_2 = Integer(b2l(b'<Redacted 2>'))

assert secret_1.nbits() == 271
assert secret_2.nbits() == 247

real_secret = Mod(secret_1, 2^1337 + 1337)/secret_2 + 1337^1337
not_secret_anymore = hex(real_secret^2)
print(not_secret_anymore)

# assert flag == b"ghctf{" + secret_1 + secret_2 + b"}"
# 0xaf67951fc756caf05e1cb834854880fa6b3919aa390a42a3f2cdcc1943b959192cebea290e4bbe41b517056b95903e9f6ec10d490fdde72cf17a7ab3e65d61fc9c0a750dc20d52626f78c7200744fb9bcc0e7b9f33dd5a83df5d05de7258404b5c56ced4b57e63ab0c7c4761ce76d789734d705e8e137a2000c678c5b90b1df6169499ef39184622d4f83a03985ba8038fdb05aae52d5f2c04f8b8f7a4ac2a54b3d0be67c71752
```

**Flag format:** ghctf{...}

## 🔧 Mathematical Analysis

### Problem Structure

The challenge implements the following transformation:

1. **Flag splitting:** The flag is divided into two parts `s1` (271 bits) and `s2` (247 bits)
2. **Secret computation:**
   ```
   real_secret = s1/s2 + 1337^1337 (mod 2^1337 + 1337)
   ```
3. **Output generation:** `not_secret_anymore = real_secret^2`

### Why Standard Approaches Fail

**Square Root Attack:** Taking the square root of `not_secret_anymore` under the ring `Z/(2^1337 + 1337)` is computationally equivalent to factoring the 1337-bit composite modulus - infeasible.

**Univariate Coppersmith:** Constructing a polynomial:

```
f(x) = (x + 1337^1337)^2 - nsr mod 2^1337 + 1337
```

where `x = s1/s2`, fails because `x` is approximately 1333 bits - not a "small root" suitable for Coppersmith's method.

### Bivariate Solution

The key insight is transforming the problem into a **bivariate polynomial** with small roots:

```
f(s1, s2) = (s1 + 1337^1337 * s2)^2 - nsr * s2^2 mod 2^1337 + 1337
```

**Why this works:**

- Eliminates the problematic division by multiplying through by `s2^2`
- Creates a polynomial with two variables that have known bounds
- `s1` bounded by `2^271` and `s2` bounded by `2^247` - both "small" enough for Coppersmith

## 🚀 Solution Implementation

### Required Tools

The solution uses **cuso** - the most robust bivariate Coppersmith implementation:

- Repository: https://github.com/keeganryan/cuso
- Handles multivariate small root finding efficiently

### Complete Solution Script

```python
from sage.all import *
import cuso
from Crypto.Util.number import long_to_bytes as l2b

# Problem parameters
p = Integer(2**1337 + 1337)
s = int("0xaf67951fc756caf05e1cb834854880fa6b3919aa390a42a3f2cdcc1943b959192cebea290e4bbe41b517056b95903e9f6ec10d490fdde72cf17a7ab3e65d61fc9c0a750dc20d52626f78c7200744fb9bcc0e7b9f33dd5a83df5d05de7258404b5c56ced4b57e63ab0c7c4761ce76d789734d705e8e137a2000c678c5b90b1df6169499ef39184622d4f83a03985ba8038fdb05aae52d5f2c04f8b8f7a4ac2a54b3d0be67c71752", 16)

# Polynomial ring setup
PR = PolynomialRing(ZZ, ['s1', 's2'])
s1, s2 = PR.gens()

# Precompute 1337^1337 mod p
c = pow(1337, 1337, p)

# Construct bivariate polynomial
f = (s1 + c*s2)**2 - s * s2**2

# Find small roots within known bounds
roots = cuso.find_small_roots(f, {s1: (0, 2**271), s2: (0, 2**247)})
print("Found roots:", roots)

# Extract solution
roots = roots[0]
s2_val, s1_val = roots[s2], roots[s1]

# Reconstruct flag
flag = "ghctf{" + (l2b(s1_val) + l2b(s2_val)).decode() + "}"
print("Flag:", flag)
```

**Expected output:**

```
ghctf{Squ4R1ng_mY_s3cr3t_w4Snt_5m4rT_b1Vari4Te_p0lyN0MiaLs_4r3_s0Lvabl3}
```
