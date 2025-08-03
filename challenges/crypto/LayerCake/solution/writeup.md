# LayerCake - Crypto Challenge Writeup

## Challenge Description

Many layers, many bases. Only one true flag beneath.

## Given

We are provided with the following encoded string:

```
6cBWBH2vdZsBByKF2y8kXcUyWsbrdxM25Xo4RSSRYYoPXDL8KV1rAhr6aKeQOHChKZq2eyg0jJAPr3uoOQlpi8GqLOYQGdpjHZSoCEkuZN70foxWIwcQPSU0YqmfKguKObocgM9hyGxHDlkjZXAl6EjdEKf6l2euWObDRufYtXVjeM12DdaoLfzmxTK8Vj18vTZq2o5
```

## Solution

This challenge involves multiple layers of base encoding. As the name "LayerCake" suggests, we need to peel back each layer to reach the final flag. The key is to use a cryptanalysis tool like dCode.fr to identify and decode each encoding layer.

### Step 1: Initial Analysis

Using dCode's automatic analyzer on the given string, we can see that it suggests investigating Base62 Encoding as the most likely encoding method.

### Step 2: Base62 Decoding

Decoding the initial string using Base62 gives us:

```
2skSSqGTdadZB2etLefaBcTqosASDwcbwgFkZJgmcA95V68P1gkpp5ZymcX86QSmQ4HXrhJMdHQp1G9WV1MSBPHuBQM8kPXu5mT7Y7pxz2ve6oRofiaFCUxanYtegn7qSjNhHrDeH2EPoDvTnzLY
```

### Step 3: Base58 Decoding

The result from Step 2 appears to be Base58 encoded. Decoding it gives us:

```
AY96ZA409JS8%6AZ09.A8GIAOS9:G8KB9*IB71A07A0C9FH871A769H%6HM8*H9*IBJB9INA*H9-CBBY8UF6HN9.IB4099T9L092G6INATB9
```

### Step 4: Base45 Decoding

Continuing with the pattern, we decode the Base58 result using Base45, which gives us:

```
M5UGG5DGPNGTA4RTL5BDI4ZTONPUIMBTONHF65C7JUZTI3S7JUYHEM27KMZWG5LSGF2HS7I=
```

### Step 6: Base32 Decoding (Final Layer)

Finally, decoding the Base45 result using Base32 reveals our flag:

```
ghctf{M0r3_B4s3s_D03sN_t_M34n_M0r3_S3cur1ty}
```
