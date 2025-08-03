import h5py, json, re

with h5py.File('model.h5', 'r') as f:
    raw = f.attrs['model_config']
    # 1) Decode bytes if needed
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode('utf-8')
    # 2) First-level parse
    cfg0 = json.loads(raw)
    # 3) If that yields a string, parse again
    cfg = json.loads(cfg0) if isinstance(cfg0, str) else cfg0

    # Inspect top‐level structure
    print("Top‐level keys:", cfg.keys())
    layers = cfg['config']['layers']

    # List every layer’s name & class
    print("\nAll layers:")
    for L in layers:
        print(f" • {L['name']}  ({L['class_name']})")

    # Search the raw JSON for any “lambda” occurrences
    print("\n\nSearching raw JSON for ‘lambda…’ snippets:")
    for m in re.finditer(r'(lambda[^\"]+)', raw):
        snippet = m.group(1)
        print(" …", snippet)

### Found StealthLambda custom layer, starting to inspect it

with h5py.File('model.h5', 'r') as f:
    # pull & decode the model_config attribute
    raw = f.attrs['model_config']
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode('utf-8')
    cfg0 = json.loads(raw)
    cfg  = json.loads(cfg0) if isinstance(cfg0, str) else cfg0

layers = cfg['config']['layers']

for layer in layers:
    if layer['class_name'].endswith('StealthLambda'):
        # pretty-print the entire layer dict
        print(json.dumps(layer, indent=2))
        break
else:
    raise RuntimeError("No StealthLambda found")