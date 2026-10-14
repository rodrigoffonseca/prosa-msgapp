// "Número de segurança": 60 dígitos que as duas pessoas comparam (ou leem por
// QR code) para confirmar que não há intermediário na conversa. Segue o
// esquema do Signal: resumo iterado de cada identidade, ordenado.

import { sha512 } from '@noble/hashes/sha2.js';

import { concat, utf8 } from './bytes.js';

const ITERATIONS = 5200;
const VERSION = new Uint8Array([0, 0]);

function displayable(identityKey: Uint8Array, stableId: string): string {
  const id = utf8.encode(stableId);
  let hash = sha512(concat(VERSION, identityKey, id));
  for (let i = 0; i < ITERATIONS; i++) hash = sha512(concat(hash, identityKey));
  let out = '';
  for (let i = 0; i < 30; i += 5) {
    let chunk = 0;
    for (let j = 0; j < 5; j++) chunk = chunk * 256 + hash[i + j]!;
    out += String(chunk % 100000).padStart(5, '0');
  }
  return out;
}

/**
 * Número de segurança de uma conversa. É o mesmo para os dois lados.
 * @param stableId identificador estável de cada usuário (ID da conta).
 */
export function safetyNumber(
  localIdentity: Uint8Array,
  localId: string,
  remoteIdentity: Uint8Array,
  remoteId: string,
): string {
  const parts = [displayable(localIdentity, localId), displayable(remoteIdentity, remoteId)].sort();
  return parts.join('');
}

/** Formata em 12 blocos de 5 dígitos para exibição. */
export function formatSafetyNumber(n: string): string {
  return n.match(/.{5}/g)!.join(' ');
}
