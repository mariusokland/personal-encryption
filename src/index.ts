export { deriveKey, encrypt, decrypt, generateSalt, encodeBase64, decodeBase64 } from './encryption';
export { initializeKey, getKey, clearKey, isKeyAvailable } from './key-manager';
export { keyToRecoveryPhrase, isValidRecoveryPhrase, createRecoveryBackup, recoverEncryptionKey } from './recovery';
