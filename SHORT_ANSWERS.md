# Short-Answer Questions

## 1. Password Length Hiding
To prevent an adversary from learning password lengths through ciphertext size analysis, all passwords are padded to a fixed length prior to encryption. Assuming the maximum password length is 64 characters (at most 256 bytes in UTF-8), each plaintext buffer is standardized to 258 bytes:
- Bytes 0–1 encode the actual password length as a 16-bit big-endian unsigned integer.
- The UTF-8 password bytes are written starting at offset 2.
- Any remaining space up to 258 bytes is filled with zero bytes.

Because AES-GCM appends a constant 16-byte authentication tag, every single encrypted record stored in the key-value store produces a ciphertext of exactly 274 bytes (368 Base64 characters). On lookup, `get()` decrypts the block, reads the 2-byte prefix and extracts the original string. This ensures uniform ciphertext size for all inputs from 0 to 64 characters while avoiding any data loss.

## 2. Preventing Swap Attacks
In a swap attack, an adversary alters the serialized database by exchanging ciphertext values between different domain keys (e.g., placing the record for `google.com` under `evil.com`), tricking the user into disclosing credentials for the wrong service.

To defend against this, the implementation uses AES-GCM and binds the domain name as Additional Authenticated Data (`additionalData: stringToBuffer(name)`). AES-GCM computes its GMAC authentication tag over both the ciphertext and this associated data.

When retrieving credentials via `get(name)`, decryption is executed with `additionalData` set to `name`. If an adversary swapped the ciphertext originally created for domain $d_1$ into the slot for domain $d_2$, the authentication tag verification fails because the tag was generated under $d_1 \ne d_2$. `subtle.decrypt` rejects the operation, and the password manager immediately throws an exception. This check operates independently on each record without needing a trusted checksum.

## 3. Rollback Defense and Trusted Storage
Yes, it is necessary to assume that some trusted external storage (or state) exists to protect against rollback attacks.

Under the defined threat model, the adversary has full read and write access to the disk where the database file is stored. Every valid serialization produced by `dump()` is completely self-consistent: all internal MACs, AEAD tags, and hash structures verify properly. As a result, a snapshot of the database from an earlier point in time is cryptographically indistinguishable to the client from the latest version. Without an external, tamper-proof reference point (such as a trusted SHA-256 hash, hardware monotonic counter, or secure element) that the adversary cannot overwrite, the client has no way to determine whether a presented database state is fresh or an authentic older state.

## 4. Randomized MACs vs. Deterministic HMAC
Because deterministic HMAC produces the identical tag for a given key and input, domain tags can serve directly as keys in an in-memory hash table, achieving $O(1)$ lookups.

If a randomized MAC were used instead:
- **Lookup Method:** The MAC of a domain name would change on every run due to internal randomness or nonces. Consequently, the tag could not be used as a dictionary key. The database would have to store entries as an unordered list of `(randomTag, ciphertext)` pairs. To look up a domain $d$, the manager would iterate through the list sequentially and run `Verify(key, d, randomTag)` on each record until finding a match or reaching the end.
- **Performance Penalty:** Lookup runtime increases from $O(1)$ to $O(n)$ where $n$ is the number of stored domains. In addition, each lookup requires up to $n$ cryptographic MAC verifications (averaging $n/2$) rather than a single HMAC computation.

## 5. Concealing the Number of Records
To limit leakage about the number of records $k$ so that only $\lfloor \log_2(k) \rfloor$ is revealed, the database can pad the total entry count to the next power-of-two boundary:

1. Define a bucket target size $N = 2^{\lfloor \log_2(k) \rfloor + 1} - 1$ (or $2^{\lceil \log_2(k) \rceil}$).
2. Populate the key-value store with $N - k$ dummy records. Each dummy record has:
   - A pseudorandom lookup key generated to be indistinguishable from legitimate HMAC tags (e.g., using $\text{HMAC}(k_{\text{mac}}, \text{"dummy:"} \parallel j)$).
   - An encrypted payload padded to the same 258-byte size as real records.
3. Because dummy entries have valid formatting and identical length to real entries, an adversary inspecting the serialized KVS can only observe the total count $N$.
4. Any two databases with true sizes $k_1$ and $k_2$ satisfying $\lfloor \log_2(k_1) \rfloor = \lfloor \log_2(k_2) \rfloor$ (such as $k=9$ and $k=14$, both having $\lfloor \log_2 \rfloor = 3$) pad to the exact same total count, revealing only the logarithmic bucket. When querying a real domain, the deterministic tag will never match a dummy key, preserving correct functionality.

## 6. Multi-User Support for Specific Sites
To allow Alice and Bob to share access to a specific site (e.g., `nytimes`) without giving either party access to the other's private passwords, we can implement an envelope encryption model:

1. **Per-Site Symmetric Key:** For `nytimes`, generate a fresh random 256-bit AES key $K_{\text{site}}$. The actual login credentials for `nytimes` are encrypted under $K_{\text{site}}$.
2. **Key Encapsulation:** Alice and Bob each have an asymmetric key pair $(\text{pk}_A, \text{sk}_A)$ and $(\text{pk}_B, \text{sk}_B)$, with private keys secured by their respective master passwords. The site key $K_{\text{site}}$ is encrypted twice:
   - $E_A = \text{Encrypt}_{\text{pk}_A}(K_{\text{site}})$
   - $E_B = \text{Encrypt}_{\text{pk}_B}(K_{\text{site}})$
3. **Access & Update:** To retrieve the password, Alice uses $\text{sk}_A$ to decrypt $E_A$, obtaining $K_{\text{site}}$, and then decrypts the site record. Bob does the same with $\text{sk}_B$ and $E_B$. When updating the password, either user encrypts the new secret under $K_{\text{site}}$.
4. **Isolation:** Because all other website credentials in Alice's vault are encrypted under keys derived solely from her own secret key (which Bob does not have), Bob cannot access any of Alice's other credentials, and Alice cannot access Bob's private entries.
