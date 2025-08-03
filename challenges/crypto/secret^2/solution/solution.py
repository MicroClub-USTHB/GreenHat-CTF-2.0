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