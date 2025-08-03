## CIFAR-10 Classification CTF — Solution Writeup

### Challenge Recap

Participants received a folder of PNG images (`images/`) where each image is a CIFAR-10 sample. The goal was to:

1. Classify each image into one of the 10 classes (labels 0–9) using a pre-trained CIFAR-10 model.
2. Record the predicted labels in sorted filename order to form a long digit string.
3. Split the string into 3-digit chunks, converting each chunk from decimal to its ASCII character.
4. Reveal the hidden flag printed as: `ghctf{n1c3_cl4551f1c4t10n}`.

### Environment & Dependencies

* **Python 3.7+**
* **PyTorch** & **Torchvision** (for loading the pre-trained ResNet20 model)
* **Pillow** (for image I/O)

Install via:

```bash
pip install torch torchvision pillow
```

### Solution Script Overview

The core solver, `solution.py`, performs the following steps:

1. **Load the Model**

   ```python
   model = torch.hub.load(
     'chenyaofo/pytorch-cifar-models',
     'cifar10_resnet20',
     pretrained=True
   )
   model.eval()
   ```

   We pull a ResNet20 fine-tuned on CIFAR-10.

2. **Define Preprocessing**

   ```python
   transform = transforms.Compose([
     transforms.Resize((32, 32)),
     transforms.ToTensor(),
     transforms.Normalize(
       mean=[0.4914, 0.4822, 0.4465],
       std =[0.2470, 0.2435, 0.2616]
     ),
   ])
   ```

   Ensures images match the model's training distribution.

3. **Iterate & Infer**

   ```python
   files = sorted(os.listdir(image_dir))
   for fname in files:
     img = Image.open(os.path.join(image_dir, fname))
     # Convert non-RGB images
     if img.mode != 'RGB':
       img = img.convert('RGB')

     x = transform(img).unsqueeze(0)
     logits = model(x)
     pred = logits.argmax(dim=1).item()  # 0–9
     pred_labels.append(str(pred))
   ```

   * We also print each image’s mode and sample pixel for debugging.

4. **Decode Flag**

   ```python
   digit_str = ''.join(pred_labels)
   chars = [chr(int(digit_str[i:i+3])) for i in range(0, len(digit_str), 3)]
   flag = ''.join(chars)
   print(flag)
   ```

   Groups the predicted digits into ASCII codes.

### Debugging & Gotchas

* **All zeros output** often indicates images were opened in grayscale or palette mode. Converting to `RGB` fixes this.
* **Missing weights**: If offline, the Hub download may fail silently—ensure the model’s state dict is present.

### Running the Solver

```bash
python solution.py
```

Expected output:

```
Found 78 images.
... (per-file predictions) ...
Full digit sequence: 103104099116102123110049099051095099108052053053049102049099052116049048110125
Decoded flag:
ghctf{n1c3_cl4551f1c4t10n}
```

### Conclusion

This writeup demonstrates how to leverage a pre-trained vision model to solve a classification-based CTF, then perform simple numeric decoding to extract the hidden flag. Feel free to adapt or extend this approach for other image-to-text challenges!
