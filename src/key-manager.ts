import { deriveKey } from './encryption';

let _key: Uint8Array | null = null;

export async function initializeKey(password: string, salt: Uint8Array): Promise<void> {
  _key = await deriveKey(password, salt);
}

export function getKey(): Uint8Array | null {
  return _key;
}

export function clearKey(): void {
  if (_key) _key.fill(0);
  _key = null;
}

export function isKeyAvailable(): boolean {
  return _key !== null;
}
