# Personal Encryption

Client-side encryption library used by [Personal Hub](https://personalhub.io).

This is the exact encryption code that protects user data in Personal Hub. We open-sourced it so anyone can verify our privacy claims.

## Architecture overview

Personal Hub uses two independent encryption layers:

**Layer 1: Personal Vault** encrypts all user data at rest. Your encryption key is derived from your password and never leaves your device. Our servers store only ciphertext.

**Layer 2: Personal MCP** encrypts data shared with AI services. Each AI connection gets its own encryption key, separate from your vault key. The share key is embedded in the connection URL and never stored on our servers.

Both layers use XSalsa20-Poly1305 authenticated encryption via TweetNaCl. Same algorithm, different keys, different purposes.

```
Your device                    Our servers              AI service
──────────                     ───────────              ──────────

Password
  │
  ├─ derive vault key
  │    │
  │    ├─ encrypt ──────────► Vault (ciphertext)
  │    │                       Cannot read.
  │    │
  │    ├─ decrypt ◄──────────
  │    │
  │    │  Select data to share
  │    │    │
  │    │    ├─ generate share key
  │    │    │    │
  │    │    │    ├─ re-encrypt ──► MCP layer (ciphertext)
  │    │    │    │                  Cannot read.
  │    │    │    │                    │
  │    │    │    │                    ├─ request + key ──► decrypt in
  │    │    │    │                    │                    memory (~50ms)
  │    │    │    │                    │                      │
  │    │    │    │                    │                      ├──────► AI reads
  │    │    │    │                    │                      │        data
  │    │    │    │                    │                      │
  │    │    │    │                    │   ◄── discard key ───┘
  │    │    │    │                    │
  │    │    │    ├─ embedded in URL (never stored on server)
  │    │    │    │
  │    │    │    └─ stored in browser (encrypted with vault key)
```

---

## Layer 1: Personal Vault

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

---

## Layer 2: Personal MCP

Personal MCP lets users share selected data from their vault with AI services (Claude, ChatGPT, or any MCP-compatible service). Each connection is encrypted independently.

### Share key generation (share-key.ts)

When a user creates an AI connection, the browser generates a new encryption key specifically for that connection.

- `generateShareKey()` generates a random 32-byte key using TweetNaCl's `randomBytes`
- `encryptWithShareKey(plaintext, shareKey)` encrypts data using XSalsa20-Poly1305 with the share key, returns `{ ciphertext, nonce }` as base64 strings
- `decryptWithShareKey(ciphertext, nonce, shareKey)` decrypts and returns the original plaintext

The share key is completely independent from the vault key. Compromising a share key does not compromise the vault. Revoking a connection invalidates only that connection's share key.

### Token system (token.ts)

Each AI connection is identified by a token that contains the share key.

- `createToken(userId, shareKey)` creates a URL-safe token encoding the user ID and share key
- `parseToken(token)` extracts the user ID and share key from a token
- `hashToken(token)` computes a SHA-256 hash of the token for server-side lookup
- `buildMcpUrl(token)` constructs the full MCP endpoint URL

The token is the only place the share key exists outside the browser. It is embedded in the connection URL that the user pastes into their AI service settings. The server stores only the SHA-256 hash of the token for revocation lookup. The full token (and therefore the share key) is never stored on our servers.

### How data flows through Personal MCP

**Setup (one time per connection):**
1. User selects which data to share (specific fields from specific dimensions)
2. Browser decrypts selected data from the vault using the vault key
3. Browser generates a new share key for this connection
4. Browser re-encrypts selected data with the share key
5. Browser uploads ciphertext to the MCP shared data table (server cannot read it)
6. Browser creates a token containing the share key
7. Token is embedded in the connection URL
8. User pastes the URL into their AI service settings

**Reading (every AI request):**
1. AI service sends an MCP request to the connection URL
2. Server extracts the token from the URL
3. Server verifies the token hash matches a non-revoked connection
4. Server retrieves the encrypted shared data for this connection
5. Server decrypts data in memory using the share key from the token
6. Server sends the decrypted data to the AI service
7. Server discards the share key from memory

The decryption in step 5-6 happens in server memory for approximately 50 milliseconds per request. The share key is not written to disk, not logged, and not persisted. This is the only moment the data is readable by the server process.

**Suggestions (AI writes back):**
1. AI calls a suggest tool with proposed data (e.g., a new interest)
2. Server encrypts the suggestion with the share key
3. Suggestion is stored encrypted in the suggestions table
4. User sees the suggestion in Personal Hub
5. Browser decrypts the suggestion using the share key (retrieved from the token stored in browser localStorage, encrypted with the vault key)
6. User approves, edits, or dismisses
7. If approved, browser encrypts the data with the vault key and saves to the vault

**Revoking a connection:**
1. User clicks Disconnect in Personal Hub
2. Server deletes all shared data for that connection's token ID
3. Server marks the token as revoked
4. Browser deletes the token from localStorage
5. The connection URL becomes permanently invalid
6. Other connections are not affected (different keys, different data)

### Per-connection isolation

Each AI connection has:
- Its own share key (generated independently)
- Its own encrypted copy of shared data
- Its own token and URL
- Its own list of shared dimensions and field exclusions

Revoking connection A has zero effect on connection B. They share nothing.

### Field-level exclusions

Users can exclude specific fields from a connection. For example, share "Basics" but exclude "Birthday" and "Phone." Exclusions are applied in the browser before encryption: excluded fields are stripped from the data before it is encrypted with the share key. The MCP server never sees excluded fields because they are never in the ciphertext.

---

## Where data is readable

| Location | Readable by | Duration |
|---|---|---|
| User's browser | The user | During their session |
| Personal Vault (Supabase) | No one (encrypted with vault key) | Until user decrypts |
| MCP shared layer (Supabase) | No one (encrypted with share key) | Until connection is revoked |
| MCP server memory | Server process | ~50ms per request |
| AI service | The AI service | During conversation (subject to AI service's privacy policy) |
| Suggestion queue (Supabase) | No one (encrypted with share key) | Until user approves or dismisses |

## Honest vulnerabilities

1. **MCP server memory window.** During an active request, data is plaintext in server memory for approximately 50 milliseconds. A memory dump during this window could expose data. We mitigate this by processing requests sequentially and discarding keys immediately after use.

2. **Connection URL contains the share key.** Anyone with the URL can read the shared data by making MCP requests. Users are warned to treat the URL as sensitive. We never display it in logs, analytics, or error messages.

3. **AI service data handling.** Once data is served to an AI service, it is subject to that service's privacy policy. We cannot control how Claude, ChatGPT, or other services process or retain the data.

4. **Supabase infrastructure.** Encrypted data is stored in Supabase (PostgreSQL). While the data is encrypted and we do not store decryption keys, the infrastructure provider theoretically has access to the ciphertext. An attacker who obtained both the ciphertext and the share key could decrypt the shared data.

5. **Browser storage.** Connection tokens are stored in browser localStorage, encrypted with the vault key. If an attacker has access to the user's browser and their password, they could decrypt the tokens.

---

## What this means for Personal Hub users

**Your vault:** Your encryption key is created on your device from your password. It never leaves your device and is never sent to our servers. All data is encrypted before transmission. Our servers store encrypted blobs that are meaningless without your key.

**Your AI connections:** Each AI service you connect gets its own encryption key, separate from your vault key. Our servers cannot read your shared data at rest. During an active request from your AI service, data is briefly decrypted in server memory to generate a response, then the key is discarded. You control exactly which fields each service can see, and you can revoke access instantly.

**Your suggestions:** When an AI suggests saving something to your hub, the suggestion is encrypted before storage. You review and approve suggestions in your browser. Only approved data enters your vault, encrypted with your vault key through the normal path.

If you forget your password, your 12-word recovery phrase is the only way to regain access. We cannot recover your data for you. This is a feature, not a limitation. It means no one else can access your data either.

## Security notes

- We use TweetNaCl (audited, widely reviewed) and @scure/bip39 (audited) rather than custom cryptography
- Key derivation uses 100,000 PBKDF2 iterations with SHA-256
- Each encryption operation generates a fresh random 24-byte nonce
- Encryption is authenticated (Poly1305 MAC prevents tampering)
- Recovery phrases follow the BIP39 standard used across the cryptocurrency industry for seed phrase generation
- Vault keys exist only in browser memory during a session and are wiped on logout
- Share keys exist only in connection URLs and in browser localStorage (encrypted with the vault key)
- The server stores only SHA-256 hashes of tokens, never the tokens themselves
- Per-connection encryption means revoking one connection does not affect others
- Field exclusions are applied before encryption, so excluded data never reaches the server

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
- [Privacy policy](https://personalhub.io/privacy)
- [Personal MCP documentation](https://personalhub.io/docs/mcp)
- [How we protect your data](https://personalhub.io/#encryption)
