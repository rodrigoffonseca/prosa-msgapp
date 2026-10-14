import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { concat } from './bytes.js';
import {
  type IdentityKeyPair,
  type KeyPair,
  dh,
  generateKeyPair,
  identityDHPrivate,
  identityDHPublic,
  verifySignedPreKey,
} from './keys.js';

const X3DH_INFO = new TextEncoder().encode('Prosa_X3DH_v1');

/** Pacote de chaves públicas publicado no servidor por cada usuário. */
export interface PreKeyBundle {
  identityKey: Uint8Array;
  signedPreKey: { id: number; publicKey: Uint8Array; signature: Uint8Array };
  oneTimePreKey?: { id: number; publicKey: Uint8Array };
}

export interface X3DHResult {
  sharedSecret: Uint8Array;
  /** Dados associados: identidade do iniciador || identidade do respondente. */
  associatedData: Uint8Array;
}

function kdf(dhs: Uint8Array[]): Uint8Array {
  // Prefixo de 32 bytes 0xFF, como na especificação X3DH para X25519.
  const ikm = concat(new Uint8Array(32).fill(0xff), ...dhs);
  return hkdf(sha256, ikm, new Uint8Array(32), X3DH_INFO, 32);
}

/** Lado de quem inicia a conversa (Alice). */
export function x3dhInitiate(
  identity: IdentityKeyPair,
  bundle: PreKeyBundle,
): X3DHResult & { ephemeral: KeyPair } {
  if (!verifySignedPreKey(bundle.identityKey, bundle.signedPreKey.publicKey, bundle.signedPreKey.signature)) {
    throw new Error('assinatura da signed prekey inválida');
  }
  const ephemeral = generateKeyPair();
  const dhs = [
    dh(identityDHPrivate(identity), bundle.signedPreKey.publicKey),
    dh(ephemeral.privateKey, identityDHPublic(bundle.identityKey)),
    dh(ephemeral.privateKey, bundle.signedPreKey.publicKey),
  ];
  if (bundle.oneTimePreKey) dhs.push(dh(ephemeral.privateKey, bundle.oneTimePreKey.publicKey));
  return {
    ephemeral,
    sharedSecret: kdf(dhs),
    associatedData: concat(identity.publicKey, bundle.identityKey),
  };
}

/** Lado de quem recebe a primeira mensagem (Bob). */
export function x3dhRespond(
  identity: IdentityKeyPair,
  signedPreKey: KeyPair,
  oneTimePreKey: KeyPair | undefined,
  remoteIdentityKey: Uint8Array,
  remoteEphemeral: Uint8Array,
): X3DHResult {
  const dhs = [
    dh(signedPreKey.privateKey, identityDHPublic(remoteIdentityKey)),
    dh(identityDHPrivate(identity), remoteEphemeral),
    dh(signedPreKey.privateKey, remoteEphemeral),
  ];
  if (oneTimePreKey) dhs.push(dh(oneTimePreKey.privateKey, remoteEphemeral));
  return { sharedSecret: kdf(dhs), associatedData: concat(remoteIdentityKey, identity.publicKey) };
}
