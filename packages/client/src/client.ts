import {
  decrypt,
  decryptAttachment,
  encrypt,
  encryptAttachment,
  equal,
  fromBase64,
  generateIdentityKeyPair,
  generateOneTimePreKeys,
  generateSignedPreKey,
  hasSession,
  initiateSession,
  pad,
  safetyNumber,
  toBase64,
  unpad,
  utf8,
} from '@prosa/crypto';

import { Api, ApiError, type Envelope, type Group, type OutgoingMessage, type User, parseEnvelope } from './api.js';
import type { AttachmentPointer, Payload, ReceivedMessage } from './messages.js';
import { validatePayload } from './messages.js';
import type { ClientStorage } from './storage.js';

const PREKEY_BATCH = 100;
const PREKEY_MIN = 20;

export type Target = { userId: string } | { groupId: string };

export interface IdentityChange {
  userId: string;
  previous: Uint8Array;
  current: Uint8Array;
}

interface Events {
  message: ReceivedMessage;
  identityChanged: IdentityChange;
  decryptionError: { envelopeId: string; from: string; error: unknown };
  connection: 'connected' | 'disconnected';
}

type Listener<T> = (e: T) => void;

export interface ClientOptions {
  serverUrl: string;
  storage: ClientStorage;
  /**
   * O que fazer quando a chave de identidade de um contato muda (ex.: ele
   * reinstalou o app, ou há um ataque). 'accept' segue o comportamento usual
   * de mensageiros e emite 'identityChanged'; 'reject' recusa a comunicação
   * até que o app chame trustIdentity().
   */
  identityChangePolicy?: 'accept' | 'reject';
}

export class IdentityChangedError extends Error {
  constructor(readonly userId: string) {
    super(`a chave de segurança de ${userId} mudou`);
    this.name = 'IdentityChangedError';
  }
}

export class ProsaClient {
  readonly api: Api;
  private readonly storage: ClientStorage;
  private readonly policy: 'accept' | 'reject';
  private readonly listeners = new Map<keyof Events, Set<Listener<never>>>();
  private queue: Promise<unknown> = Promise.resolve();
  private readonly seen = new Set<string>();
  private userId: string | undefined;
  private ws: WebSocket | undefined;
  private wantConnection = false;
  private reconnectDelay = 1000;

  constructor(opts: ClientOptions) {
    this.api = new Api(opts.serverUrl);
    this.storage = opts.storage;
    this.policy = opts.identityChangePolicy ?? 'accept';
  }

  /** Restaura a sessão salva no aparelho. Devolve false se não houver login. */
  async restore(): Promise<boolean> {
    const auth = await this.storage.getAuth();
    if (!auth) return false;
    this.api.token = auth.token;
    this.userId = auth.userId;
    return true;
  }

  get currentUserId(): string {
    if (!this.userId) throw new Error('não autenticado');
    return this.userId;
  }

  // ---- eventos ----

  on<K extends keyof Events>(event: K, fn: Listener<Events[K]>): () => void {
    let set = this.listeners.get(event);
    if (!set) this.listeners.set(event, (set = new Set()));
    set.add(fn as Listener<never>);
    return () => set.delete(fn as Listener<never>);
  }

  private emit<K extends keyof Events>(event: K, data: Events[K]): void {
    for (const fn of this.listeners.get(event) ?? []) (fn as Listener<Events[K]>)(data);
  }

  /** Serializa operações que alteram sessões criptográficas. */
  private exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  // ---- cadastro ----

  requestCode(phone: string) {
    return this.api.requestCode(phone);
  }

  /**
   * Confirma o código recebido por SMS, cria (ou reaproveita) as chaves deste
   * aparelho e publica as chaves públicas no servidor.
   */
  async verifyCode(phone: string, code: string): Promise<{ user: User; newAccount: boolean }> {
    const r = await this.api.verify(phone, code);
    this.api.token = r.token;
    this.userId = r.user.id;
    await this.storage.setAuth({ token: r.token, userId: r.user.id });
    if (!(await this.storage.hasIdentityKeyPair())) {
      await this.storage.setIdentityKeyPair(generateIdentityKeyPair());
      await this.storage.setLocalRegistrationId(1 + (crypto.getRandomValues(new Uint32Array(1))[0]! % 0x7ffffffe));
    }
    await this.publishKeys();
    return { user: r.user, newAccount: r.new_account };
  }

  private async publishKeys(): Promise<void> {
    const identity = await this.storage.getIdentityKeyPair();
    const spk = generateSignedPreKey(identity, Date.now() % 0x7fffffff);
    await this.storage.putSignedPreKey(spk.id, spk.keyPair);
    const otks = await this.newOneTimePreKeys();
    await this.api.putKeys({
      registrationId: await this.registrationId(),
      identityKey: identity.publicKey,
      signedPreKey: { id: spk.id, publicKey: spk.keyPair.publicKey, signature: spk.signature },
      oneTimePreKeys: otks,
    });
  }

  private async registrationId(): Promise<number> {
    const id = await this.storage.getLocalRegistrationId();
    if (id === undefined) throw new Error('instalação sem registration_id');
    return id;
  }

  private async newOneTimePreKeys() {
    const start = await this.storage.nextPreKeyId();
    const keys = generateOneTimePreKeys(start, PREKEY_BATCH);
    await this.storage.putOneTimePreKeys(keys);
    await this.storage.setNextPreKeyId(start + PREKEY_BATCH);
    return keys.map((k) => ({ id: k.id, publicKey: k.keyPair.publicKey }));
  }

  private async replenishPreKeys(): Promise<void> {
    if ((await this.api.countOneTimePreKeys()) < PREKEY_MIN) {
      await this.api.addOneTimePreKeys(await this.newOneTimePreKeys());
    }
  }

  async logout(): Promise<void> {
    this.disconnect();
    try {
      await this.api.logout();
    } finally {
      await this.storage.clear();
      this.api.token = undefined;
      this.userId = undefined;
    }
  }

  /** Apaga a conta no servidor e os dados locais. */
  async deleteAccount(): Promise<void> {
    this.disconnect();
    await this.api.deleteMe();
    await this.storage.clear();
    this.api.token = undefined;
    this.userId = undefined;
  }

  // ---- perfil e contatos ----

  setProfile(fields: { username?: string; displayName?: string }) {
    return this.api.updateMe({ username: fields.username, display_name: fields.displayName });
  }

  findByUsername(username: string) {
    return this.api.getUserByUsername(username);
  }

  findByPhone(phone: string) {
    return this.api.lookupPhone(phone);
  }

  // ---- grupos ----

  createGroup(name: string, memberIds: string[]) {
    return this.api.createGroup(name, memberIds);
  }

  listGroups(): Promise<Group[]> {
    return this.api.listGroups();
  }

  addGroupMembers(groupId: string, userIds: string[]) {
    return this.api.addGroupMembers(groupId, userIds);
  }

  removeGroupMember(groupId: string, userId: string) {
    return this.api.removeGroupMember(groupId, userId);
  }

  leaveGroup(groupId: string) {
    return this.api.removeGroupMember(groupId, this.currentUserId);
  }

  // ---- segurança ----

  /** Número de segurança (60 dígitos) da conversa com um contato. */
  async safetyNumber(userId: string): Promise<string | undefined> {
    const remote = await this.storage.getTrustedIdentity(userId);
    if (!remote) return undefined;
    const local = await this.storage.getIdentityKeyPair();
    return safetyNumber(local.publicKey, this.currentUserId, remote, userId);
  }

  /** Aceita explicitamente uma nova chave de identidade de um contato. */
  trustIdentity(userId: string, key: Uint8Array) {
    return this.storage.setTrustedIdentity(userId, key);
  }

  /**
   * Verifica a chave de identidade de um contato (TOFU: a primeira chave vista
   * é registrada como confiável). Devolve false se a mensagem/sessão deve ser
   * recusada.
   */
  private async checkIdentity(userId: string, key: Uint8Array): Promise<boolean> {
    const trusted = await this.storage.getTrustedIdentity(userId);
    if (!trusted) {
      await this.storage.setTrustedIdentity(userId, key);
      return true;
    }
    if (equal(trusted, key)) return true;
    this.emit('identityChanged', { userId, previous: trusted, current: key });
    if (this.policy === 'reject') return false;
    await this.storage.setTrustedIdentity(userId, key);
    return true;
  }

  // ---- envio ----

  sendText(target: Target, text: string) {
    if (!text) throw new Error('mensagem vazia');
    return this.send(target, { kind: 'text', text });
  }

  sendImage(target: Target, data: Uint8Array, meta: { mime: string; width?: number; height?: number; caption?: string }) {
    const { caption, ...rest } = meta;
    return this.sendAttachment(target, 'image', data, rest, caption);
  }

  sendVoice(target: Target, data: Uint8Array, meta: { mime: string; durationMs: number }) {
    return this.sendAttachment(target, 'voice', data, meta);
  }

  private async sendAttachment(
    target: Target,
    kind: 'image' | 'voice',
    data: Uint8Array,
    meta: Pick<AttachmentPointer, 'mime' | 'width' | 'height' | 'durationMs'>,
    caption?: string,
  ) {
    const enc = encryptAttachment(data);
    const { id } = await this.api.uploadAttachment(enc.ciphertext);
    const attachment: AttachmentPointer = {
      id,
      key: toBase64(enc.key),
      digest: toBase64(enc.digest),
      mime: meta.mime,
      size: data.length,
      ...(meta.width !== undefined && { width: meta.width }),
      ...(meta.height !== undefined && { height: meta.height }),
      ...(meta.durationMs !== undefined && { durationMs: meta.durationMs }),
    };
    return this.send(target, { kind, attachment, ...(caption && { text: caption }) });
  }

  /** Baixa, verifica e decifra o anexo de uma mensagem recebida. */
  async downloadAttachment(pointer: AttachmentPointer): Promise<Uint8Array> {
    const ciphertext = await this.api.downloadAttachment(pointer.id);
    return decryptAttachment(ciphertext, fromBase64(pointer.key), fromBase64(pointer.digest));
  }

  private async send(target: Target, content: Pick<Payload, 'kind' | 'text' | 'attachment'>): Promise<Payload> {
    const payload: Payload = {
      v: 1,
      id: randomId(),
      ...content,
      ...('groupId' in target && { groupId: target.groupId }),
      senderRegistrationId: await this.registrationId(),
      sentAt: Date.now(),
    };
    const plaintext = pad(utf8.encode(JSON.stringify(payload)));
    const groupId = 'groupId' in target ? target.groupId : undefined;
    let members = groupId
      ? (await this.api.getGroup(groupId)).members.map((m) => m.user_id)
      : [(target as { userId: string }).userId];

    // Até 3 tentativas: o servidor pode pedir para refazer sessões (410, o
    // contato reinstalou o app) ou atualizar a lista do grupo (409).
    for (let attempt = 0; ; attempt++) {
      const recipients = members.filter((id) => id !== this.currentUserId);
      const messages = await this.exclusive(async () => {
        const out: OutgoingMessage[] = [];
        for (const to of recipients) out.push(await this.encryptFor(to, plaintext));
        return out;
      });
      try {
        if (messages.length > 0) await this.api.sendMessages(groupId, messages);
        return payload;
      } catch (err) {
        if (!(err instanceof ApiError) || attempt >= 2) throw err;
        if (err.status === 410 && Array.isArray(err.body.stale)) {
          await this.exclusive(async () => {
            for (const id of err.body.stale as string[]) await this.storage.deleteSession(id);
          });
          continue;
        }
        if (err.status === 409 && groupId && Array.isArray(err.body.members)) {
          members = err.body.members as string[];
          continue;
        }
        throw err;
      }
    }
  }

  private async encryptFor(userId: string, plaintext: Uint8Array): Promise<OutgoingMessage> {
    if (!(await hasSession(this.storage, userId))) {
      const b = await this.api.getBundle(userId);
      if (!(await this.checkIdentity(userId, b.identity_key))) throw new IdentityChangedError(userId);
      await initiateSession(this.storage, userId, {
        identityKey: b.identity_key,
        signedPreKey: { id: b.signed_prekey.id, publicKey: b.signed_prekey.public_key, signature: b.signed_prekey.signature },
        oneTimePreKey: b.one_time_prekey && { id: b.one_time_prekey.id, publicKey: b.one_time_prekey.public_key },
      });
      await this.storage.setRemoteRegistrationId(userId, b.registration_id);
    }
    return {
      to: userId,
      // Desconhecido (0) força o servidor a responder 410 e a sessão a ser refeita.
      registrationId: (await this.storage.getRemoteRegistrationId(userId)) ?? 0,
      ciphertext: await encrypt(this.storage, userId, plaintext),
    };
  }

  // ---- recebimento ----

  /** Busca e processa todas as mensagens pendentes no servidor. */
  async sync(): Promise<void> {
    for (;;) {
      const envelopes = await this.api.pendingEnvelopes(100);
      if (envelopes.length === 0) break;
      for (const env of envelopes) await this.process(env);
      await this.api.ack(envelopes.map((e) => e.id));
      if (envelopes.length < 100) break;
    }
    await this.replenishPreKeys();
  }

  private process(env: Envelope): Promise<void> {
    return this.exclusive(async () => {
      if (this.seen.has(env.id)) return;
      this.seen.add(env.id);
      if (this.seen.size > 10_000) this.seen.delete(this.seen.values().next().value!);
      try {
        const r = await decrypt(this.storage, env.sender_id, env.ciphertext);
        if (!(await this.checkIdentity(env.sender_id, r.remoteIdentity))) {
          throw new IdentityChangedError(env.sender_id);
        }
        const payload = validatePayload(JSON.parse(utf8.decode(unpad(r.plaintext))));
        // O servidor marca envelopes de grupo; o conteúdo cifrado diz o grupo
        // verdadeiro. Se divergirem, a mensagem foi manipulada.
        if ((payload.groupId ?? null) !== (env.group_id ?? null)) throw new Error('grupo da mensagem não confere');
        await this.storage.setRemoteRegistrationId(env.sender_id, payload.senderRegistrationId);
        this.emit('message', { ...payload, from: env.sender_id, envelopeId: env.id, serverTimestamp: env.server_timestamp });
      } catch (error) {
        // A mensagem não pode ser recuperada depois (as chaves avançaram),
        // então ela é confirmada mesmo assim e o app é avisado.
        this.emit('decryptionError', { envelopeId: env.id, from: env.sender_id, error });
      }
    });
  }

  /** Abre a conexão em tempo real (WebSocket), com reconexão automática. */
  connect(): void {
    this.wantConnection = true;
    if (this.ws) return;
    const ws = new WebSocket(this.api.webSocketUrl());
    this.ws = ws;
    ws.onmessage = (ev) => {
      const msg = JSON.parse(String(ev.data));
      if (msg.type === 'ready') {
        this.reconnectDelay = 1000;
        this.emit('connection', 'connected');
        this.sync().catch(() => ws.close());
      } else if (msg.type === 'envelope') {
        const env = parseEnvelope(msg.envelope);
        this.process(env)
          .then(() => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify({ type: 'ack', ids: [env.id] })))
          .catch(() => undefined);
      }
    };
    ws.onclose = () => {
      this.ws = undefined;
      this.emit('connection', 'disconnected');
      if (this.wantConnection) {
        setTimeout(() => this.wantConnection && this.connect(), this.reconnectDelay);
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, 60_000);
      }
    };
  }

  disconnect(): void {
    this.wantConnection = false;
    this.ws?.close();
    this.ws = undefined;
  }
}

function randomId(): string {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6]! & 0x0f) | 0x40;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
