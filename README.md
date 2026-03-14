# Personal Encryption

Client-side encryption library used by [Personal Hub](https://personalhub.io).

This is the exact encryption code that protects user data in Personal Hub. We open-sourced it so anyone can verify our privacy claims.

## What it does

All user data in Personal Hub is encrypted on the user's device before it leaves the browser. This package contains the three modules that make that possible: encryption, key management, and key recovery.

### Encryption (encryption.ts)

Authenticated symmetric encryption using XSalsa20-Poly1305 via TweetNaCl.

- `generateSalt()` creates a random 16-byte salt for key derivation
- `deriveKey(password, salt)` derives a 32-byte encryption key using PBKDF2 with 100,000 iterations of SHA-256
- `encrypt(plaintext, key)` encrypts data with a fresh random nonce, returns base64-encoded nonce + ciphertext
- `decrypt(encrypted, key)` decrypts and returns the original plaintext

Every encryption operation generates a unique nonce. Encrypting the same data twice produces different ciphertext. The Poly1305 MAC ensures any tampering is detected on decryption.

### Key management (key-manager.ts)

Manages the user's encryption key in memory during a browser session.

- `initializeKey(password, salt)` derives the key from the user's password and stores it in memory
- `getKey()` returns the current key, or null if not initialized
- `clearKey()` wipes the key from memory (called on logout)
- `isKeyAvailable()` returns whether a key is currently loaded

The key exists only in browser memory. It is never written to disk, never sent to a server, and never persisted between sessions. On logout, it is wiped.

### Key recovery (recovery.ts)

BIP39 mnemonic-based key recovery so users can regain access if they forget their password.

- `keyToRecoveryPhrase(key)` converts the encryption key into a deterministic 12-word recovery phrase using the BIP39 standard
- `isValidRecoveryPhrase(phrase)` validates that a phrase is a legitimate BIP39 mnemonic
- `createRecoveryBackup(key, phrase)` encrypts the user's encryption key under a key derived from the recovery phrase, producing a backup that can be stored safely
- `recoverEncryptionKey(phrase, encryptedKey, salt)` re-derives the recovery key from the phrase and decrypts the original encryption key

The recovery phrase is shown to the user once at signup. It is the only way to recover data if the password is forgotten. Personal Hub does not store recovery phrases and cannot recover data on behalf of users.

## What this means for Personal Hub users

Your encryption key is created on your device from your password. It never leaves your device and is never sent to our servers. All data is encrypted before transmission. Our servers store encrypted blobs that are meaningless without your key.

If you forget your password, your 12-word recovery phrase is the only way to regain access. We cannot recover your data for you. This is a feature, not a limitation. It means no one else can access your data either.

## Security notes

- We use TweetNaCl (audited, widely reviewed) and @scure/bip39 (audited) rather than custom cryptography
- Key derivation uses 100,000 PBKDF2 iterations with SHA-256
- Each encryption operation generates a fresh random 24-byte nonce
- Encryption is authenticated (Poly1305 MAC prevents tampering)
- Recovery phrases follow the BIP39 standard used across the cryptocurrency industry for seed phrase generation
- Keys exist only in browser memory during a session and are wiped on logout

## Run tests

```bash
npm install
npm test
```

The test suite covers encryption round-trips, key derivation consistency, key manager lifecycle, recovery phrase generation, and full end-to-end recovery (encrypt data, lose key, recover from phrase, decrypt original data).

## License

AGPL-3.0. See [LICENSE](./LICENSE) for the full text.

This means you can read, audit, and verify this code freely. If you modify and distribute it, or run a modified version as a network service, you must also open-source your modifications under AGPL-3.0. This protects the code from being used in closed-source products that claim privacy without transparency.

## Why AGPL-3.0

We chose AGPL over MIT because this is security-critical code. If someone forks it and weakens the encryption in a closed-source product, users of that product would have no way to know. AGPL ensures that any service using this code (or a modified version) must make their version available for inspection. Transparency is the point.

## Links

- [Personal Hub](https://personalhub.io)
- [About Personal](https://personalhub.io/about)
- [How we protect your data](https://personalhub.io/#encryption)
