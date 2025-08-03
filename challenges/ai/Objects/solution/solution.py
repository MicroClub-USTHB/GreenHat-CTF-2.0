#!/usr/bin/env python3
import os
import torch
from torchvision import transforms
from PIL import Image

# 1) Load a pretrained CIFAR-10 model
model = torch.hub.load(
    'chenyaofo/pytorch-cifar-models',
    'cifar10_resnet20',
    pretrained=True
)
model.eval()

# 2) Preprocessing to match CIFAR-10 stats
transform = transforms.Compose([
    transforms.Resize((32, 32)),
    transforms.ToTensor(),
    transforms.Normalize(
        mean=[0.4914, 0.4822, 0.4465],
        std =[0.2470, 0.2435, 0.2616]
    ),
])

# 3) Inference over images/
image_dir = 'images'
files = sorted(f for f in os.listdir(image_dir) if f.lower().endswith('.png'))
print(f"Found {len(files)} images.\n")

pred_labels = []
with torch.no_grad():
    for fname in files:
        path = os.path.join(image_dir, fname)
        img = Image.open(path)

        # --- DEBUG: print out the mode & pixel at (0,0) ---
        if img.mode != 'RGB':
            print(f"[!] {fname} opened in mode={img.mode}, converting to RGB")
            img = img.convert('RGB')
        else:
            print(f"{fname}: mode=RGB, sample pixel={img.getpixel((0,0))}")

        # Preprocess + infer
        x = transform(img).unsqueeze(0)     # [1,3,32,32]
        logits = model(x)                   # [1,10]
        pred = logits.argmax(dim=1).item()  # 0–9
        pred_labels.append(str(pred))
        print(f"  → predicted class: {pred}\n")

# 4) Build the flag
digit_str = ''.join(pred_labels)
print("Full digit sequence:", digit_str)

# split into 3-digit chunks and decode ASCII
chars = [chr(int(digit_str[i:i+3])) for i in range(0, len(digit_str), 3)]
flag = ''.join(chars)
print("\nDecoded flag:\n", flag)