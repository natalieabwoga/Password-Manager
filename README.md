# ICS 3201: Programming Assignment 1 — Password Manager

A secure password manager library and local web interface built with the Web Crypto API (`SubtleCrypto`).

---

## Overview

- **Key Derivation:** Uses PBKDF2 with SHA-256 (100,000 iterations) and a 128-bit random salt to derive a master key $k$.
- **Sub-Key Separation:** Uses HMAC as a PRF on $k$ to derive separate keys:
  - `domainMacKey`: deterministic HMAC tag for domain lookups ($O(1)$ lookup time).
  - `aesKey`: AES-GCM encryption key for record encryption.
  - `authTag`: authentication token stored in the vault dump to authenticate the master password without saving the password or raw keys.
- **Swap Attack Defense:** Binds the domain name as Additional Authenticated Data (`additionalData`) in AES-GCM. Swapped ciphertexts trigger an AEAD authentication tag mismatch and throw an exception.
- **Rollback Attack Defense:** `dump()` computes a SHA-256 hash of the serialized state, which `load()` verifies against `trustedDataCheck`.
- **Length Hiding:** Plaintext passwords are padded to a uniform 258-byte buffer (2-byte length prefix + UTF-8 payload + zeros) before AES-GCM encryption, ensuring all stored records produce identical ciphertext lengths.

---

## Project Structure

```
├── password-manager.js          # Core library (submission file)
├── lib.js                       # SubtleCrypto conversion helpers
├── index.html                   # Local vault interface
├── server.js                    # Local static development server
├── package.json                 # Project configuration
├── SHORT_ANSWERS.md             # Written answers to assignment questions
└── test/
    ├── test-password-manager.js # Course test suite
    └── comprehensive-test.js    # Security & edge case tests
```

---

## Running the Code

### Run Tests
```bash
npm test
```

### Start Web Interface
```bash
npm start
```
Then open [http://localhost:3000](http://localhost:3000) in your browser.
