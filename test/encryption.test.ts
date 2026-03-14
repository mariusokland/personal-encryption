import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  encrypt,
  decrypt,
  deriveKey,
  generateSalt,
  initializeKey,
  getKey,
  clearKey,
  isKeyAvailable,
  keyToRecoveryPhrase,
  isValidRecoveryPhrase,
  createRecoveryBackup,
  recoverEncryptionKey,
} from '../src/index';

describe('encryption', () => {
  let key: Uint8Array;
  let salt: Uint8Array;

  beforeEach(async () => {
    salt = generateSalt();
    key = await deriveKey('test-password-123', salt);
  });

  it('should encrypt and decrypt a string correctly', () => {
    const plaintext = 'Hello, this is sensitive data.';
    const encrypted = encrypt(plaintext, key);
    const decrypted = decrypt(encrypted, key);
    expect(decrypted).toBe(plaintext);
  });

  it('should encrypt and decrypt unicode correctly', () => {
    const plaintext = 'Norsk tekst med æøå: Blåbærsyltetøy er godt! 🔒';
    const encrypted = encrypt(plaintext, key);
    const decrypted = decrypt(encrypted, key);
    expect(decrypted).toBe(plaintext);
  });

  it('should encrypt and decrypt empty string', () => {
    const encrypted = encrypt('', key);
    const decrypted = decrypt(encrypted, key);
    expect(decrypted).toBe('');
  });

  it('should encrypt and decrypt large data', () => {
    const plaintext = 'x'.repeat(100000);
    const encrypted = encrypt(plaintext, key);
    const decrypted = decrypt(encrypted, key);
    expect(decrypted).toBe(plaintext);
  });

  it('should produce different ciphertext for different keys', async () => {
    const otherSalt = generateSalt();
    const otherKey = await deriveKey('different-password', otherSalt);
    const plaintext = 'same data';
    const encrypted1 = encrypt(plaintext, key);
    const encrypted2 = encrypt(plaintext, otherKey);
    expect(encrypted1).not.toBe(encrypted2);
  });

  it('should produce different ciphertext each time (unique nonce)', () => {
    const plaintext = 'same data same key';
    const encrypted1 = encrypt(plaintext, key);
    const encrypted2 = encrypt(plaintext, key);
    expect(encrypted1).not.toBe(encrypted2);
    expect(decrypt(encrypted1, key)).toBe(plaintext);
    expect(decrypt(encrypted2, key)).toBe(plaintext);
  });

  it('should fail to decrypt with wrong key', async () => {
    const plaintext = 'secret';
    const encrypted = encrypt(plaintext, key);
    const wrongKey = await deriveKey('wrong-password', salt);
    expect(() => decrypt(encrypted, wrongKey)).toThrow();
  });

  it('should fail to decrypt corrupted data', () => {
    const encrypted = encrypt('test', key);
    const corrupted = encrypted.slice(0, -4) + 'XXXX';
    expect(() => decrypt(corrupted, key)).toThrow();
  });
});

describe('key derivation', () => {
  it('should produce consistent key for same password and salt', async () => {
    const salt = generateSalt();
    const key1 = await deriveKey('my-password', salt);
    const key2 = await deriveKey('my-password', salt);
    expect(key1).toEqual(key2);
  });

  it('should produce different keys for different passwords', async () => {
    const salt = generateSalt();
    const key1 = await deriveKey('password-a', salt);
    const key2 = await deriveKey('password-b', salt);
    expect(key1).not.toEqual(key2);
  });

  it('should produce different keys for different salts', async () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    const key1 = await deriveKey('same-password', salt1);
    const key2 = await deriveKey('same-password', salt2);
    expect(key1).not.toEqual(key2);
  });

  it('should produce a 32-byte key', async () => {
    const salt = generateSalt();
    const key = await deriveKey('test', salt);
    expect(key.length).toBe(32);
  });
});

describe('salt generation', () => {
  it('should produce 16-byte salts', () => {
    const salt = generateSalt();
    expect(salt.length).toBe(16);
  });

  it('should produce unique salts', () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    expect(salt1).not.toEqual(salt2);
  });
});

describe('key manager', () => {
  afterEach(() => {
    clearKey();
  });

  it('should start with no key available', () => {
    expect(isKeyAvailable()).toBe(false);
    expect(getKey()).toBeNull();
  });

  it('should store key after initialization', async () => {
    const salt = generateSalt();
    await initializeKey('test-password', salt);
    expect(isKeyAvailable()).toBe(true);
    expect(getKey()).not.toBeNull();
    expect(getKey()!.length).toBe(32);
  });

  it('should clear key on clearKey()', async () => {
    const salt = generateSalt();
    await initializeKey('test-password', salt);
    expect(isKeyAvailable()).toBe(true);
    clearKey();
    expect(isKeyAvailable()).toBe(false);
    expect(getKey()).toBeNull();
  });

  it('should produce working keys', async () => {
    const salt = generateSalt();
    await initializeKey('test-password', salt);
    const key = getKey()!;
    const encrypted = encrypt('hello', key);
    const decrypted = decrypt(encrypted, key);
    expect(decrypted).toBe('hello');
  });
});

describe('recovery', () => {
  let key: Uint8Array;

  beforeEach(async () => {
    const salt = generateSalt();
    key = await deriveKey('test-password-123', salt);
  });

  it('should generate a valid 12-word recovery phrase from a key', () => {
    const phrase = keyToRecoveryPhrase(key);
    const words = phrase.split(' ');
    expect(words.length).toBe(12);
    expect(isValidRecoveryPhrase(phrase)).toBe(true);
  });

  it('should generate the same phrase for the same key (deterministic)', () => {
    const phrase1 = keyToRecoveryPhrase(key);
    const phrase2 = keyToRecoveryPhrase(key);
    expect(phrase1).toBe(phrase2);
  });

  it('should generate different phrases for different keys', async () => {
    const otherSalt = generateSalt();
    const otherKey = await deriveKey('other-password', otherSalt);
    const phrase1 = keyToRecoveryPhrase(key);
    const phrase2 = keyToRecoveryPhrase(otherKey);
    expect(phrase1).not.toBe(phrase2);
  });

  it('should validate correct BIP39 phrases', () => {
    const phrase = keyToRecoveryPhrase(key);
    expect(isValidRecoveryPhrase(phrase)).toBe(true);
  });

  it('should reject invalid phrases', () => {
    expect(isValidRecoveryPhrase('not a valid phrase at all nope')).toBe(false);
    expect(isValidRecoveryPhrase('')).toBe(false);
    expect(isValidRecoveryPhrase('abandon abandon abandon')).toBe(false);
  });

  it('should backup and recover encryption key via recovery phrase', async () => {
    const phrase = keyToRecoveryPhrase(key);
    const backup = await createRecoveryBackup(key, phrase);

    expect(backup).toBeDefined();
    expect(backup.encryptedKey).toBeDefined();
    expect(backup.recoverySalt).toBeDefined();

    const recoveredKey = await recoverEncryptionKey(
      phrase,
      backup.encryptedKey,
      backup.recoverySalt,
    );

    expect(recoveredKey).toEqual(key);
  });

  it('should fail recovery with wrong phrase', async () => {
    const phrase = keyToRecoveryPhrase(key);
    const backup = await createRecoveryBackup(key, phrase);

    const otherSalt = generateSalt();
    const otherKey = await deriveKey('other', otherSalt);
    const wrongPhrase = keyToRecoveryPhrase(otherKey);

    await expect(
      recoverEncryptionKey(wrongPhrase, backup.encryptedKey, backup.recoverySalt)
    ).rejects.toThrow();
  });

  it('should work end-to-end: encrypt data, lose key, recover, decrypt', async () => {
    const plaintext = 'This is my important data';
    const encrypted = encrypt(plaintext, key);

    const phrase = keyToRecoveryPhrase(key);
    const backup = await createRecoveryBackup(key, phrase);

    clearKey();
    expect(getKey()).toBeNull();

    const recoveredKey = await recoverEncryptionKey(
      phrase,
      backup.encryptedKey,
      backup.recoverySalt,
    );

    const decrypted = decrypt(encrypted, recoveredKey);
    expect(decrypted).toBe(plaintext);
  });
});
