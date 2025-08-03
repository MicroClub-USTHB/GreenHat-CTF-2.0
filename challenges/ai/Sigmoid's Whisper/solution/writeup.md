## Challenge: Sigmoid’s Whisper – The Hidden Monad

> **Description**
> You’re given a Keras/TensorFlow `.h5` model. It behaves like any ordinary CNN—but one of its layers conceals a phantom Lambda function (“the monad”) that whispers out the flag at inference time. Your job is to extract that function without running the model, decode its payload, and recover the flag.

---

### 1. Peek inside the HDF5

Keras HDF5 models bundle two main things:

* **Weights** under `/model_weights`
* **Architecture JSON** in the file’s `model_config` attribute

Opening with `h5py` in read‐only mode lets you inspect:

```python
import h5py
with h5py.File('model.h5','r') as f:
    print("Datasets:", list(f.keys()))
    print("Attrs:", list(f.attrs.keys()))
    raw = f.attrs['model_config']
```

You’ll see `model_weights` and `model_config` in `f.attrs`.

---

### 2. Decode & parse the model\_config

The `model_config` attribute is a (possibly double-encoded) JSON string describing every layer. Decode and load it:

```python
import json

# raw may be bytes or a str
raw = raw.decode() if isinstance(raw, (bytes,bytearray)) else raw
cfg0 = json.loads(raw)
cfg  = json.loads(cfg0) if isinstance(cfg0, str) else cfg0

layers = cfg['config']['layers']
```

---

### 3. Spot the stealth layer

Rather than a plain `Lambda`, the hidden code lives in a custom layer:

```python
for L in layers:
    if L['class_name'].endswith('StealthLambda'):
        stealth_cfg = L['config']
        break
```

This `stealth_cfg` dict contains a Base64-encoded string under `"function"`.

---

### 4. Extract & decode the Base64 payload

Pull out the Base64 blob, decode it to get the Python source, and locate the integer list:

```python
import base64

b64 = stealth_cfg['function']
src = base64.b64decode(b64).decode('utf-8')
print(src)
```

You’ll see something like:

```python
def sneaky_payload(x):
    print("You have been pwned!")
    items = [ 103,104,99,116,102,123, ... ,125 ]
    return x
```

---

### 5. Turn integers into the flag

Those numbers are ASCII codes. A simple list‐comprehension reveals the flag:

```python
items = [103,104,99,116,102,123,75,51,114,52,115,95,76,52,109,98,100,52,
         95,49,110,106,51,99,116,49,48,110,95,49,115,95,110,48,116,
         95,115,48,95,115,52,102,51,125]

flag = ''.join(chr(c) for c in items)
print(flag)
# ➜ ghctf{K3r4s_L4mbd4_1nj3ct10n_1s_n0t_s0_s4f3}
```

---

### 6. (Optional) Safely view the rest of the model

If you still want to explore layer shapes or weights without triggering the payload:

```python
from tensorflow.keras.models import model_from_json

# Rebuild architecture without executing the payload
arch_json = json.dumps(cfg)
model = model_from_json(arch_json)
model.load_weights('model.h5')
model.summary()
```

---

## The Flag

```
ghctf{K3r4s_L4mbd4_1nj3ct10n_1s_n0t_s0_s4f3}
```

---

### Lessons Learned

* **Never trust hidden code**: Lambda (and custom) layers serialize arbitrary Python.
* **Static analysis wins**: Extracting and reading source is safer than blindly loading and running models.
* **Steganography in ML**: Model configs are fertile ground to hide CTF payloads.