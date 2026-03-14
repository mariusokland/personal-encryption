import { entropyToMnemonic, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { generateSalt, deriveKey, encrypt, decrypt, encodeBase64, decodeBase64 } from './encryption';

export function keyToRecoveryPhrase(key: Uint8Array): string {
  return entropyToMnemonic(key.slice(0, 16), wordlist); // deterministic 12 words from first 128 bits
}

export function isValidRecoveryPhrase(phrase: string): boolean {
  return validateMnemonic(phrase.trim().toLowerCase(), wordlist);
}

function normalizePhrase(phrase: string): string {
  return phrase.trim().toLowerCase().replace(/\s+/g, ' ');
}

export async function createRecoveryBackup(
  encryptionKey: Uint8Array,
  phrase: string
): Promise<{ encryptedKey: string; recoverySalt: string }> {
  const salt = generateSalt();
  const recoveryKey = await deriveKey(normalizePhrase(phrase), salt);
  const encryptedKey = encrypt(encodeBase64(encryptionKey), recoveryKey);
  return { encryptedKey, recoverySalt: encodeBase64(salt) };
}

export async function recoverEncryptionKey(
  phrase: string,
  encryptedKey: string,
  recoverySaltB64: string
): Promise<Uint8Array> {
  const salt = decodeBase64(recoverySaltB64);
  const recoveryKey = await deriveKey(normalizePhrase(phrase), salt);
  const decryptedB64 = decrypt(encryptedKey, recoveryKey);
  return decodeBase64(decryptedB64);
}
