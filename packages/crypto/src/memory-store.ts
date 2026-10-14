import type { IdentityKeyPair, KeyPair, OneTimePreKey, SignedPreKey } from './keys.js';
import type { ProtocolStore } from './session.js';

/** ProtocolStore em memória, útil para testes e ferramentas. */
export class InMemoryProtocolStore implements ProtocolStore {
  readonly signedPreKeys = new Map<number, KeyPair>();
  readonly oneTimePreKeys = new Map<number, KeyPair>();
  readonly sessions = new Map<string, string>();

  constructor(readonly identity: IdentityKeyPair) {}

  addSignedPreKey(k: SignedPreKey): void {
    this.signedPreKeys.set(k.id, k.keyPair);
  }

  addOneTimePreKeys(keys: OneTimePreKey[]): void {
    for (const k of keys) this.oneTimePreKeys.set(k.id, k.keyPair);
  }

  async getIdentityKeyPair() {
    return this.identity;
  }
  async getSignedPreKey(id: number) {
    return this.signedPreKeys.get(id);
  }
  async getOneTimePreKey(id: number) {
    return this.oneTimePreKeys.get(id);
  }
  async removeOneTimePreKey(id: number) {
    this.oneTimePreKeys.delete(id);
  }
  async loadSession(address: string) {
    return this.sessions.get(address);
  }
  async storeSession(address: string, record: string) {
    this.sessions.set(address, record);
  }
}
