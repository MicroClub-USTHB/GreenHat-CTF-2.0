from Crypto.Util.number import long_to_bytes, inverse

# Facteurs donnés
p = 241171862595544214041784729954324633933
q = 324132381365139613756988823394162008647
n = p * q
e = 65537
c = 76765561337861954510489019428335917947548662515701118558623386348287937790750

# Calcul de phi(n)
phi = (p - 1) * (q - 1)

# Calcul de la clé privée d
d = inverse(e, phi)

# Déchiffrement
m = pow(c, d, n)

# Conversion en bytes
flag = long_to_bytes(m)

print("Flag déchiffré :", flag.decode())
