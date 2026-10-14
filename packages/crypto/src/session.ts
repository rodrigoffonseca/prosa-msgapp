// Sessões 1:1 cifradas de ponta a ponta: X3DH para estabelecer a sessão e
// Double Ratchet para cada mensagem. Este módulo também define o formato
// binário que trafega (opaco) pelo servidor.

import { concat, equal, fromBase64, readU32, toBase64, u32 } from './bytes.js';
import type { IdentityKeyPair, KeyPair } from './keys.js';
import {
  type RatchetState,
  deserializeRatchet,
  initReceiver,
  initSender,
  ratchetDecrypt,
  ratchetEncrypt,
  serializeRatchet,
} from './ratchet.js';
import { type PreKeyBundle, x3dhInitiate, x3dhRespond } from './x3dh.js';

const VERSION = 1;
const TYPE_PREKEY = 1;
const TYPE_MESSAGE = 2;
/** Quantas sessões anteriores manter por contato (ver initiation race). */
const MAX_ARCHIVED_SESSIONS = 4;

/**
 * Armazenamento local das chaves e sessões. No aplicativo deve ser
 * implementado sobre armazenamento seguro do sistema (Keychain/Keystore +
 * banco local cifrado).
 */
export interface ProtocolStore {
  getIdentityKeyPair(): Promise<IdentityKeyPair>;
  getSignedPreKey(id: number): Promise<KeyPair | undefined>;
  getOneTimePreKey(id: number): Promise<KeyPair | undefined>;
  removeOneTimePreKey(id: number): Promise<void>;
  loadSession(address: string): Promise<string | undefined>;
  storeSession(address: string, record: string): Promise<void>;
}

export class NoSessionError extends Error {
  constructor(address: string) {
    super(`não há sessão com ${address}`);
    this.name = 'NoSessionError';
  }
}

interface PendingPreKey {
  signedPreKeyId: number;
  oneTimePreKeyId?: number;
  baseKey: Uint8Array;
}

interface Session {
  remoteIdentity: Uint8Array;
  ratchet: RatchetState;
  /** Presente enquanto o outro lado não responder: enviamos PreKey messages. */
  pending?: PendingPreKey;
  /** Chave efêmera do iniciador, para reconhecer PreKey messages repetidas. */
  remoteBaseKey?: Uint8Array;
}

interface SessionRecord {
  current: Session;
  archived: Session[];
}

export interface DecryptResult {
  plaintext: Uint8Array;
  /** Chave de identidade do remetente (para verificação/TOFU pelo app). */
  remoteIdentity: Uint8Array;
  /** true se esta mensagem criou uma nova sessão. */
  newSession: boolean;
}

/** Inicia uma sessão a partir do pacote de chaves obtido no servidor. */
export async function initiateSession(store: ProtocolStore, address: string, bundle: PreKeyBundle): Promise<void> {
  const identity = await store.getIdentityKeyPair();
  const x = x3dhInitiate(identity, bundle);
  const session: Session = {
    remoteIdentity: bundle.identityKey,
    ratchet: initSender(x.sharedSecret, bundle.signedPreKey.publicKey, x.associatedData),
    pending: {
      signedPreKeyId: bundle.signedPreKey.id,
      oneTimePreKeyId: bundle.oneTimePreKey?.id,
      baseKey: x.ephemeral.publicKey,
    },
  };
  await saveRecord(store, address, pushSession(await loadRecord(store, address), session));
}

export async function hasSession(store: ProtocolStore, address: string): Promise<boolean> {
  return (await loadRecord(store, address)) !== undefined;
}

/** Identidade do contato registrada na sessão atual. */
export async function sessionRemoteIdentity(store: ProtocolStore, address: string): Promise<Uint8Array | undefined> {
  return (await loadRecord(store, address))?.current.remoteIdentity;
}

export async function encrypt(store: ProtocolStore, address: string, plaintext: Uint8Array): Promise<Uint8Array> {
  const record = await loadRecord(store, address);
  if (!record) throw new NoSessionError(address);
  const s = record.current;
  const inner = ratchetEncrypt(s.ratchet, plaintext);
  let out: Uint8Array;
  if (s.pending) {
    const identity = await store.getIdentityKeyPair();
    out = concat(
      new Uint8Array([VERSION, TYPE_PREKEY]),
      identity.publicKey,
      s.pending.baseKey,
      u32(s.pending.signedPreKeyId),
      new Uint8Array([s.pending.oneTimePreKeyId === undefined ? 0 : 1]),
      u32(s.pending.oneTimePreKeyId ?? 0),
      inner,
    );
  } else {
    out = concat(new Uint8Array([VERSION, TYPE_MESSAGE]), inner);
  }
  await saveRecord(store, address, record);
  return out;
}

export async function decrypt(store: ProtocolStore, address: string, data: Uint8Array): Promise<DecryptResult> {
  if (data.length < 2 || data[0] !== VERSION) throw new Error('versão de mensagem não suportada');
  if (data[1] === TYPE_MESSAGE) return decryptMessage(store, address, data.slice(2));
  if (data[1] === TYPE_PREKEY) return decryptPreKeyMessage(store, address, data.slice(2));
  throw new Error('tipo de mensagem desconhecido');
}

async function decryptMessage(store: ProtocolStore, address: string, inner: Uint8Array): Promise<DecryptResult> {
  const record = await loadRecord(store, address);
  if (!record) throw new NoSessionError(address);
  const candidates = [record.current, ...record.archived];
  for (const s of candidates) {
    let plaintext: Uint8Array;
    try {
      plaintext = ratchetDecrypt(s.ratchet, inner);
    } catch {
      continue;
    }
    // O outro lado respondeu: a sessão está estabelecida.
    delete s.pending;
    record.archived = candidates.filter((c) => c !== s);
    record.current = s;
    await saveRecord(store, address, record);
    return { plaintext, remoteIdentity: s.remoteIdentity, newSession: false };
  }
  throw new Error('não foi possível decifrar a mensagem');
}

async function decryptPreKeyMessage(store: ProtocolStore, address: string, data: Uint8Array): Promise<DecryptResult> {
  if (data.length < 73) throw new Error('mensagem truncada');
  const remoteIdentity = data.slice(0, 32);
  const baseKey = data.slice(32, 64);
  const signedPreKeyId = readU32(data, 64);
  const hasOneTime = data[68] === 1;
  const oneTimePreKeyId = readU32(data, 69);
  const inner = data.slice(73);

  // PreKey message repetida de uma sessão que já conhecemos.
  const record = await loadRecord(store, address);
  const known = record && [record.current, ...record.archived].find((s) => s.remoteBaseKey && equal(s.remoteBaseKey, baseKey));
  if (known) {
    if (!equal(known.remoteIdentity, remoteIdentity)) throw new Error('identidade não confere com a sessão');
    const plaintext = ratchetDecrypt(known.ratchet, inner);
    record.archived = [record.current, ...record.archived].filter((s) => s !== known);
    record.current = known;
    await saveRecord(store, address, record);
    return { plaintext, remoteIdentity, newSession: false };
  }

  const identity = await store.getIdentityKeyPair();
  const signedPreKey = await store.getSignedPreKey(signedPreKeyId);
  if (!signedPreKey) throw new Error('signed prekey desconhecida');
  let oneTimePreKey: KeyPair | undefined;
  if (hasOneTime) {
    oneTimePreKey = await store.getOneTimePreKey(oneTimePreKeyId);
    // Chave já usada: possível repetição (replay) de mensagem antiga.
    if (!oneTimePreKey) throw new Error('one-time prekey desconhecida ou já utilizada');
  }
  const x = x3dhRespond(identity, signedPreKey, oneTimePreKey, remoteIdentity, baseKey);
  const session: Session = {
    remoteIdentity,
    ratchet: initReceiver(x.sharedSecret, signedPreKey, x.associatedData),
    remoteBaseKey: baseKey,
  };
  const plaintext = ratchetDecrypt(session.ratchet, inner);
  if (hasOneTime) await store.removeOneTimePreKey(oneTimePreKeyId);
  await saveRecord(store, address, pushSession(record, session));
  return { plaintext, remoteIdentity, newSession: true };
}

function pushSession(record: SessionRecord | undefined, session: Session): SessionRecord {
  if (!record) return { current: session, archived: [] };
  return { current: session, archived: [record.current, ...record.archived].slice(0, MAX_ARCHIVED_SESSIONS) };
}

// ---- serialização ----

function serializeSession(s: Session): unknown {
  return {
    remoteIdentity: toBase64(s.remoteIdentity),
    ratchet: serializeRatchet(s.ratchet),
    pending: s.pending && {
      signedPreKeyId: s.pending.signedPreKeyId,
      oneTimePreKeyId: s.pending.oneTimePreKeyId,
      baseKey: toBase64(s.pending.baseKey),
    },
    remoteBaseKey: s.remoteBaseKey && toBase64(s.remoteBaseKey),
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function deserializeSession(o: any): Session {
  return {
    remoteIdentity: fromBase64(o.remoteIdentity),
    ratchet: deserializeRatchet(o.ratchet),
    pending: o.pending && {
      signedPreKeyId: o.pending.signedPreKeyId,
      oneTimePreKeyId: o.pending.oneTimePreKeyId,
      baseKey: fromBase64(o.pending.baseKey),
    },
    remoteBaseKey: o.remoteBaseKey ? fromBase64(o.remoteBaseKey) : undefined,
  };
}

async function loadRecord(store: ProtocolStore, address: string): Promise<SessionRecord | undefined> {
  const raw = await store.loadSession(address);
  if (!raw) return undefined;
  const o = JSON.parse(raw);
  return { current: deserializeSession(o.current), archived: o.archived.map(deserializeSession) };
}

async function saveRecord(store: ProtocolStore, address: string, r: SessionRecord): Promise<void> {
  await store.storeSession(
    address,
    JSON.stringify({ v: 1, current: serializeSession(r.current), archived: r.archived.map(serializeSession) }),
  );
}
