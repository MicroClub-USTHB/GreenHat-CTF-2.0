## step 1: download all files (images)
open the pcap file in wireshark and find the images in the traffic to download them.

## step 2: use steghide to extract hidden data
use steghide to extract the hidden data in some image, in the image image_mountain, you gonna find a zip file which contains an image discribing the real flag.

## repair the image to get the flag:
the image has been destructed by shifting the pixels of each line of the image to the right or left with an offset
the goal is to determine the offset and shift the pixels of each line to get a visibility of the flag 
here's a script that can do it: 
 ```python
 from PIL import Image, ImageEnhance, ImageFilter
import numpy as np

def shift_row(row, offset):
    return np.roll(row, offset, axis=0)

def repair_glitched_lines(img_path, output_path, max_offset=400, passes=2, contrast_boost=2.0):
    img = Image.open(img_path).convert("RGB")
    width, height = img.size
    img_data = np.array(img)

    for _ in range(passes):  
        repaired = img_data.copy()
        for y in range(1, height):
            current_row = img_data[y]
            best_score = float('inf')
            best_shift = 0

            for offset in range(-max_offset, max_offset + 1, 1):
                shifted = shift_row(current_row, offset)
                diff = np.abs(shifted - repaired[y - 1])
                score = np.sum(diff)

                if score < best_score:
                    best_score = score
                    best_shift = offset

            repaired[y] = shift_row(current_row, best_shift)

        img_data = repaired  

    repaired_img = Image.fromarray(img_data)

    enhancer = ImageEnhance.Contrast(repaired_img)
    enhanced_img = enhancer.enhance(contrast_boost)

    sharpened_img = enhanced_img.filter(ImageFilter.SHARPEN)

    sharpened_img.save(output_path)
    print(f"[+] Image parfaitement restaurée sauvegardée sous : {output_path}")

repair_glitched_lines("glitched_stripes.png", "final_flag_restored.png")
 ```
  

## hint: to get hidden files
dont look what's between your eyes