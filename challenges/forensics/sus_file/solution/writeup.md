# The Informant's Trail 🕵️

**Category**: Forensics  
**Difficulty**: Hard  
**Flag format**: ghctf{...}

## Challenge Description
Our intelligence agency has intercepted a suspicious image from a known informant. We believe it contains a multi-layered message that will lead us to crucial information about an upcoming operation. The informant is known for using creative hiding techniques. Can you follow the trail and piece together their complete message?

**File**: `sus.jpg`

## Solution

### Step 1: EXIF Data Analysis + Steganography
First, analyze the image for hidden metadata and steganographic content.

```bash
# Check EXIF data for clues
exiftool sus.jpg
```

The EXIF data reveals the first part of a password: `T0t4e`

Next, attempt to extract hidden files using steganography, after bruteforcing we get "password123"

```bash
# Try common passwords for steganography
steghide extract -sf sus.jpg -p password123
```

This extracts two files:
- `call_of_the_night.wav` - An audio file
- `encrypted_data.zip` - A password-protected archive

### Step 2: SSTV Audio Decoding
The WAV file contains an SSTV (Slow Scan Television) transmission that needs to be decoded.

Play the audio to identify it as SSTV

Use SSTV decoding software to convert the audio signal back to an image

The decoded image reveals the second part of the password: `M00n`

### Step 3: Final Archive Extraction
Combine both password parts to unlock the final archive:

```bash
# Complete password: SecretAg3nt_Mission007
unzip -P "T0t4eM00n" encrypted_data.zip
```

This reveals the flag file containing: **ghctf{5us_f1le}**

## Key Techniques Used
- **EXIF Data Analysis** - Metadata examination for hidden information
- **Steganography** - Hidden file extraction from images
- **SSTV Decoding** - Amateur radio image transmission format
- **Password Reconstruction** - Combining clues from multiple sources

## Tools Required
- `exiftool` - EXIF metadata analysis
- `steghide` - Steganography extraction
- SSTV decoder software (MMSSTV, QSSTV, etc.)
- `unzip` - Archive extraction
