# RSA2 Challenge Write-up

## Challenge Analysis

Nous avons un challenge RSA classique avec les paramètres suivants :

- `n = 78171610141359986845327912351123232390236978889968107877416597134344255618651`
- `c = 76765561337861954510489019428335917947548662515701118558623386348287937790750`
- `e = 65537` (valeur standard pour RSA)

L'objectif est de déchiffrer le message crypté `c` pour obtenir le flag.

## Solution

### Étape 1 : Factorisation de n

La première étape consiste à factoriser `n` pour trouver les nombres premiers `p` et `q`.

Nous utilisons le site [CrypTool Legacy - Msieve](https://legacy.cryptool.org/en/cto/msieve) pour factoriser `n`.

1. Accéder au site https://legacy.cryptool.org/en/cto/msieve
2. Saisir la valeur de `n` dans le champ de factorisation
3. Lancer la factorisation

**Résultat de la factorisation :**

- `p = 241171862595544214041784729954324633933`
- `q = 324132381365139613756988823394162008647`

Vérification : `p × q = n` ✓

### Étape 2 : Calcul de la clé privée

Une fois `p` et `q` obtenus, nous pouvons calculer la clé privée `d` :

1. Calculer `φ(n) = (p-1) × (q-1)`
2. Calculer `d = e⁻¹ mod φ(n)`

### Étape 3 : Déchiffrement

Avec la clé privée `d`, nous pouvons déchiffrer le message :

- `m = c^d mod n`
- Convertir `m` en bytes pour obtenir le flag

## Code de solution

```python
from Crypto.Util.number import long_to_bytes, inverse

# Facteurs obtenus via la factorisation
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
```

## Flag

**Flag obtenu :** `ghctf{f4ct0r1z3_n_t0_d3crypt}`
