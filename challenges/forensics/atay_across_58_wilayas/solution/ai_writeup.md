# The Algerian Tea Merchant 🍃

**Category**: Forensics  
**Difficulty**: Medium  
**Flag format**: ghctf{...}

## Story
A tea merchant has been caught selling large quantities of tea, but investigators suspect he might be hiding something more sinister. We've captured some of their network traffic - can you find what they're really planning?

**File**: `algerian_tea_challenge.pcap`

## Challenge Description
The challenge suggests that the merchant is using tea orders to communicate a hidden message. The emphasis on the number 58 and Algeria's 58 wilayas (provinces) provides a crucial hint about the encoding method used.

## Solution Approach

### Step 1: Network Traffic Analysis
First, we need to analyze the provided PCAP file to understand the network traffic patterns. The challenge hints that the merchant is communicating through tea orders, so we should look for HTTP requests or API calls related to tea orders.

### Step 2: Identifying Relevant Requests
Upon examining the traffic, we find multiple requests targeting different locations. However, the key insight is to focus only on requests related to Algerian wilayas (provinces). The challenge specifically mentions Algeria's 58 wilayas, which is our main clue.

**Important**: Not all requests are relevant. Some requests target non-Algerian locations and contain fake flags designed to mislead solvers. These must be filtered out.

### Step 3: Filtering Algerian Wilaya Requests
Extract only the network requests that correspond to Algeria's 58 wilayas. Each wilaya has a specific number (1-58), and these numbers will be crucial for the decoding process.

### Step 4: Data Extraction
From the filtered requests, extract the JSON responses and identify the wilaya numbers. These numbers represent the core data needed for decoding the hidden message.

### Step 5: Base58 Decoding
The key insight is that the wilaya numbers correspond to Base58 encoding:
- The numbers 1-58 map to Base58 characters
- Base58 uses the character set: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`
- Each wilaya number corresponds to a specific position in this character set

### Step 6: Character Mapping
Convert each wilaya number to its corresponding Base58 character:
- 10 → A
- 11 → B
- ...continuing through the Base58 alphabet...
- 58 → z

### Step 7: Flag Construction
Once all wilaya numbers are converted to their respective Base58 characters, concatenate them in the correct order to form the decoded message.

### Step 8: Final Decoding
Using a tool like CyberChef or a custom script, process the Base58 characters to reveal the final flag.

## Final Flag
**ghctf{4t4y_t0_th3_d34th}**

## Key Takeaways
- Pay attention to challenge hints (58 wilayas of Algeria)
- Filter out irrelevant data and fake flags
- Understand the encoding scheme (Base58 in this case)
- Use appropriate tools for decoding (CyberChef, custom scripts, etc.)
