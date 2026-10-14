// Cifra de anexos (fotos e áudios). Cada anexo recebe uma chave aleatória
// própria; o servidor guarda apenas o arquivo cifrado. A chave e o resumo
// (digest) viajam dentro da mensagem cifrada de ponta a ponta.

import { gcm } from '@noble/ciphers/aes.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';

import { concat, equal } from './bytes.js';

export interface EncryptedAttachment {
  /** nonce (12 bytes) || AES-256-GCM(dados). É isto que vai para o servidor. */
  ciphertext: Uint8Array;
  key: Uint8Array;
  /** SHA-256 de ciphertext, para verificar a integridade antes de decifrar. */
  digest: Uint8Array;
}

export function encryptAttachment(data: Uint8Array): EncryptedAttachment {
  const key = randomBytes(32);
  const nonce = randomBytes(12);
  const ciphertext = concat(nonce, gcm(key, nonce).encrypt(data));
  return { ciphertext, key, digest: sha256(ciphertext) };
}

export function decryptAttachment(ciphertext: Uint8Array, key: Uint8Array, digest: Uint8Array): Uint8Array {
  if (!equal(sha256(ciphertext), digest)) throw new Error('anexo corrompido ou adulterado');
  if (ciphertext.length < 12 + 16) throw new Error('anexo truncado');
  return gcm(key, ciphertext.slice(0, 12)).decrypt(ciphertext.slice(12));
}
