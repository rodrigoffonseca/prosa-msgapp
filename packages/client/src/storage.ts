import {
  type IdentityKeyPair,
  type KeyPair,
  type ProtocolStore,
  fromBase64,
  toBase64,
} from '@prosa/crypto';

/**
 * Armazenamento local do cliente: chaves, sessões, credenciais e identidades
 * confiáveis dos contatos. No app móvel, implemente sobre o Keychain/Keystore
 * e um banco local cifrado (ex.: SQLCipher).
 */
export interface ClientStorage extends ProtocolStore {
  getAuth(): Promise<{ token: string; userId: string } | undefined>;
  setAuth(auth: { token: string; userId: string } | undefined): Promise<void>;

  hasIdentityKeyPair(): Promise<boolean>;
  /** Identificador aleatório desta instalação (1 a 2^31-1). */
  getLocalRegistrationId(): Promise<number | undefined>;
  setLocalRegistrationId(id: number): Promise<void>;
  /** registration_id da instalação de um contato com quem temos sessão. */
  getRemoteRegistrationId(userId: string): Promise<number | undefined>;
  setRemoteRegistrationId(userId: string, id: number): Promise<void>;
  deleteSession(address: string): Promise<void>;
  setIdentityKeyPair(k: IdentityKeyPair): Promise<void>;
  putSignedPreKey(id: number, k: KeyPair): Promise<void>;
  putOneTimePreKeys(keys: { id: number; keyPair: KeyPair }[]): Promise<void>;
  /** Próximo ID livre para one-time prekeys. */
  nextPreKeyId(): Promise<number>;
  setNextPreKeyId(id: number): Promise<void>;

  /** Identidade confiável (TOFU) de um contato. */
  getTrustedIdentity(userId: string): Promise<Uint8Array | undefined>;
  setTrustedIdentity(userId: string, key: Uint8Array): Promise<void>;

  /** Apaga tudo (logout / reinstalação). */
  clear(): Promise<void>;
}

/**
 * Implementação simples baseada em um mapa chave→texto. Serve tanto para
 * testes (Map em memória) quanto como ponte para armazenamentos do tipo
 * chave-valor (ex.: MMKV cifrado no React Native).
 */
export class KeyValueStorage implements ClientStorage {
  constructor(
    private readonly kv: {
      get(k: string): Promise<string | undefined> | string | undefined;
      set(k: string, v: string): Promise<void> | void;
      delete(k: string): Promise<void> | void;
      keys(): Promise<string[]> | string[];
    } = new MapKV(),
  ) {}

  private async getJSON<T>(k: string): Promise<T | undefined> {
    const v = await this.kv.get(k);
    return v === undefined ? undefined : (JSON.parse(v) as T);
  }

  private async setJSON(k: string, v: unknown): Promise<void> {
    await this.kv.set(k, JSON.stringify(v));
  }

  private async getKeyPair(k: string): Promise<KeyPair | undefined> {
    const o = await this.getJSON<{ pub: string; priv: string }>(k);
    return o && { publicKey: fromBase64(o.pub), privateKey: fromBase64(o.priv) };
  }

  private setKeyPair(k: string, kp: KeyPair): Promise<void> {
    return this.setJSON(k, { pub: toBase64(kp.publicKey), priv: toBase64(kp.privateKey) });
  }

  getAuth() {
    return this.getJSON<{ token: string; userId: string }>('auth');
  }
  async setAuth(auth: { token: string; userId: string } | undefined) {
    if (auth) await this.setJSON('auth', auth);
    else await this.kv.delete('auth');
  }

  async hasIdentityKeyPair() {
    return (await this.kv.get('identity')) !== undefined;
  }
  async getIdentityKeyPair(): Promise<IdentityKeyPair> {
    const k = await this.getKeyPair('identity');
    if (!k) throw new Error('chave de identidade não gerada');
    return k;
  }
  setIdentityKeyPair(k: IdentityKeyPair) {
    return this.setKeyPair('identity', k);
  }
  getLocalRegistrationId() {
    return this.getJSON<number>('registration-id');
  }
  setLocalRegistrationId(id: number) {
    return this.setJSON('registration-id', id);
  }
  getRemoteRegistrationId(userId: string) {
    return this.getJSON<number>(`remote-registration:${userId}`);
  }
  setRemoteRegistrationId(userId: string, id: number) {
    return this.setJSON(`remote-registration:${userId}`, id);
  }
  async deleteSession(address: string) {
    await this.kv.delete(`session:${address}`);
    await this.kv.delete(`remote-registration:${address}`);
  }

  getSignedPreKey(id: number) {
    return this.getKeyPair(`spk:${id}`);
  }
  putSignedPreKey(id: number, k: KeyPair) {
    return this.setKeyPair(`spk:${id}`, k);
  }
  getOneTimePreKey(id: number) {
    return this.getKeyPair(`otk:${id}`);
  }
  async putOneTimePreKeys(keys: { id: number; keyPair: KeyPair }[]) {
    for (const k of keys) await this.setKeyPair(`otk:${k.id}`, k.keyPair);
  }
  async removeOneTimePreKey(id: number) {
    await this.kv.delete(`otk:${id}`);
  }
  async nextPreKeyId() {
    return (await this.getJSON<number>('next-prekey-id')) ?? 1;
  }
  setNextPreKeyId(id: number) {
    return this.setJSON('next-prekey-id', id);
  }

  async loadSession(address: string) {
    return (await this.kv.get(`session:${address}`)) ?? undefined;
  }
  async storeSession(address: string, record: string) {
    await this.kv.set(`session:${address}`, record);
  }

  async getTrustedIdentity(userId: string) {
    const v = await this.kv.get(`trusted:${userId}`);
    return v === undefined ? undefined : fromBase64(v);
  }
  async setTrustedIdentity(userId: string, key: Uint8Array) {
    await this.kv.set(`trusted:${userId}`, toBase64(key));
  }

  async clear() {
    for (const k of await this.kv.keys()) await this.kv.delete(k);
  }
}

class MapKV {
  private readonly m = new Map<string, string>();
  get(k: string) {
    return this.m.get(k);
  }
  set(k: string, v: string) {
    this.m.set(k, v);
  }
  delete(k: string) {
    this.m.delete(k);
  }
  keys() {
    return [...this.m.keys()];
  }
}
