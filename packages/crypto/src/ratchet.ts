// Implementação do Double Ratchet conforme a especificação do Signal
// (https://signal.org/docs/specifications/doubleratchet/), com AES-256-GCM
// como AEAD.

import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { concat, equal, fromBase64, readU32, toBase64, toHex, u32 } from './bytes.js';
import { type KeyPair, dh, generateKeyPair } from './keys.js';

const RATCHET_INFO = new TextEncoder().encode('Prosa_Ratchet_v1');
const MESSAGE_KEY_INFO = new TextEncoder().encode('Prosa_MessageKeys_v1');

/** Máximo de mensagens que podem ser puladas numa única cadeia. */
export const MAX_SKIP = 1000;
/** Máximo de chaves de mensagens puladas guardadas por sessão. */
export const MAX_STORED_SKIPPED = 2000;

export const HEADER_LENGTH = 40;

export interface RatchetState {
  rootKey: Uint8Array;
  sendingRatchet: KeyPair;
  remoteRatchet: Uint8Array | null;
  sendingChainKey: Uint8Array | null;
  receivingChainKey: Uint8Array | null;
  sendCount: number;
  recvCount: number;
  prevSendCount: number;
  /** Chaves de mensagens puladas, em ordem de inserção: [ratchetHex:n, chave]. */
  skipped: Array<[string, Uint8Array]>;
  associatedData: Uint8Array;
}

interface Header {
  ratchetKey: Uint8Array;
  prevCount: number;
  count: number;
}

function kdfRoot(rootKey: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  const out = hkdf(sha256, dhOut, rootKey, RATCHET_INFO, 64);
  return [out.slice(0, 32), out.slice(32)];
}

function kdfChain(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  return [hmac(sha256, chainKey, new Uint8Array([2])), hmac(sha256, chainKey, new Uint8Array([1]))];
}

function aead(messageKey: Uint8Array, ad: Uint8Array) {
  const out = hkdf(sha256, messageKey, new Uint8Array(32), MESSAGE_KEY_INFO, 44);
  return gcm(out.slice(0, 32), out.slice(32, 44), ad);
}

function encodeHeader(h: Header): Uint8Array {
  return concat(h.ratchetKey, u32(h.prevCount), u32(h.count));
}

function decodeHeader(b: Uint8Array): Header {
  if (b.length < HEADER_LENGTH) throw new Error('mensagem truncada');
  return { ratchetKey: b.slice(0, 32), prevCount: readU32(b, 32), count: readU32(b, 36) };
}

export function initSender(sharedSecret: Uint8Array, remoteRatchet: Uint8Array, associatedData: Uint8Array): RatchetState {
  const sendingRatchet = generateKeyPair();
  const [rootKey, sendingChainKey] = kdfRoot(sharedSecret, dh(sendingRatchet.privateKey, remoteRatchet));
  return {
    rootKey,
    sendingRatchet,
    remoteRatchet,
    sendingChainKey,
    receivingChainKey: null,
    sendCount: 0,
    recvCount: 0,
    prevSendCount: 0,
    skipped: [],
    associatedData,
  };
}

export function initReceiver(sharedSecret: Uint8Array, ownRatchet: KeyPair, associatedData: Uint8Array): RatchetState {
  return {
    rootKey: sharedSecret,
    sendingRatchet: ownRatchet,
    remoteRatchet: null,
    sendingChainKey: null,
    receivingChainKey: null,
    sendCount: 0,
    recvCount: 0,
    prevSendCount: 0,
    skipped: [],
    associatedData,
  };
}

/** Cifra e avança o estado. Devolve cabeçalho (40 bytes) || texto cifrado. */
export function ratchetEncrypt(state: RatchetState, plaintext: Uint8Array): Uint8Array {
  if (!state.sendingChainKey) throw new Error('sessão ainda não pode enviar');
  const [nextChain, messageKey] = kdfChain(state.sendingChainKey);
  state.sendingChainKey = nextChain;
  const header = encodeHeader({
    ratchetKey: state.sendingRatchet.publicKey,
    prevCount: state.prevSendCount,
    count: state.sendCount,
  });
  state.sendCount++;
  return concat(header, aead(messageKey, concat(state.associatedData, header)).encrypt(plaintext));
}

/**
 * Decifra uma mensagem. O estado só é alterado se a decifração tiver
 * sucesso; mensagens forjadas ou corrompidas não afetam a sessão.
 */
export function ratchetDecrypt(state: RatchetState, message: Uint8Array): Uint8Array {
  const header = decodeHeader(message);
  const headerBytes = message.slice(0, HEADER_LENGTH);
  const body = message.slice(HEADER_LENGTH);
  const ad = concat(state.associatedData, headerBytes);

  const skippedId = `${toHex(header.ratchetKey)}:${header.count}`;
  const idx = state.skipped.findIndex(([id]) => id === skippedId);
  if (idx >= 0) {
    const plaintext = aead(state.skipped[idx]![1], ad).decrypt(body);
    state.skipped.splice(idx, 1);
    return plaintext;
  }

  const next = cloneState(state);
  if (!next.remoteRatchet || !equal(header.ratchetKey, next.remoteRatchet)) {
    skipMessageKeys(next, header.prevCount);
    dhRatchet(next, header.ratchetKey);
  }
  skipMessageKeys(next, header.count);
  if (!next.receivingChainKey) throw new Error('mensagem inválida para esta sessão');
  const [nextChain, messageKey] = kdfChain(next.receivingChainKey);
  next.receivingChainKey = nextChain;
  next.recvCount++;
  const plaintext = aead(messageKey, ad).decrypt(body);
  Object.assign(state, next);
  return plaintext;
}

function skipMessageKeys(state: RatchetState, until: number): void {
  if (!state.receivingChainKey) return;
  if (until - state.recvCount > MAX_SKIP) throw new Error('mensagens puladas demais');
  while (state.recvCount < until) {
    const [nextChain, messageKey] = kdfChain(state.receivingChainKey);
    state.receivingChainKey = nextChain;
    state.skipped.push([`${toHex(state.remoteRatchet!)}:${state.recvCount}`, messageKey]);
    state.recvCount++;
  }
  if (state.skipped.length > MAX_STORED_SKIPPED) {
    state.skipped.splice(0, state.skipped.length - MAX_STORED_SKIPPED);
  }
}

function dhRatchet(state: RatchetState, remoteRatchet: Uint8Array): void {
  state.prevSendCount = state.sendCount;
  state.sendCount = 0;
  state.recvCount = 0;
  state.remoteRatchet = remoteRatchet;
  [state.rootKey, state.receivingChainKey] = kdfRoot(state.rootKey, dh(state.sendingRatchet.privateKey, remoteRatchet));
  state.sendingRatchet = generateKeyPair();
  [state.rootKey, state.sendingChainKey] = kdfRoot(state.rootKey, dh(state.sendingRatchet.privateKey, remoteRatchet));
}

function cloneState(s: RatchetState): RatchetState {
  return {
    ...s,
    sendingRatchet: { ...s.sendingRatchet },
    skipped: s.skipped.map(([id, k]) => [id, k] as [string, Uint8Array]),
  };
}

// ---- serialização (para guardar a sessão no aparelho) ----

const b = (x: Uint8Array | null) => (x ? toBase64(x) : null);
const u = (x: string | null) => (x ? fromBase64(x) : null);

export function serializeRatchet(s: RatchetState): unknown {
  return {
    rootKey: b(s.rootKey),
    sendingRatchet: { publicKey: b(s.sendingRatchet.publicKey), privateKey: b(s.sendingRatchet.privateKey) },
    remoteRatchet: b(s.remoteRatchet),
    sendingChainKey: b(s.sendingChainKey),
    receivingChainKey: b(s.receivingChainKey),
    sendCount: s.sendCount,
    recvCount: s.recvCount,
    prevSendCount: s.prevSendCount,
    skipped: s.skipped.map(([id, k]) => [id, b(k)]),
    associatedData: b(s.associatedData),
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function deserializeRatchet(o: any): RatchetState {
  return {
    rootKey: u(o.rootKey)!,
    sendingRatchet: { publicKey: u(o.sendingRatchet.publicKey)!, privateKey: u(o.sendingRatchet.privateKey)! },
    remoteRatchet: u(o.remoteRatchet),
    sendingChainKey: u(o.sendingChainKey),
    receivingChainKey: u(o.receivingChainKey),
    sendCount: o.sendCount,
    recvCount: o.recvCount,
    prevSendCount: o.prevSendCount,
    skipped: o.skipped.map(([id, k]: [string, string]) => [id, u(k)!]),
    associatedData: u(o.associatedData)!,
  };
}
