import { ed25519, x25519 } from '@noble/curves/ed25519.js';

/**
 * Par de chaves de identidade de longo prazo. É um par Ed25519 (para
 * assinar a signed prekey) que também é usado em X25519 (para o acordo de
 * chaves X3DH) por meio da conversão birracional Edwards → Montgomery.
 */
export interface IdentityKeyPair {
  publicKey: Uint8Array; // Ed25519, 32 bytes
  privateKey: Uint8Array; // semente Ed25519, 32 bytes
}

export interface KeyPair {
  publicKey: Uint8Array; // X25519, 32 bytes
  privateKey: Uint8Array;
}

export interface SignedPreKey {
  id: number;
  keyPair: KeyPair;
  signature: Uint8Array; // Ed25519(identidade, publicKey)
}

export interface OneTimePreKey {
  id: number;
  keyPair: KeyPair;
}

export function generateIdentityKeyPair(): IdentityKeyPair {
  const privateKey = ed25519.utils.randomSecretKey();
  return { privateKey, publicKey: ed25519.getPublicKey(privateKey) };
}

export function generateKeyPair(): KeyPair {
  const privateKey = x25519.utils.randomSecretKey();
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

export function generateSignedPreKey(identity: IdentityKeyPair, id: number): SignedPreKey {
  const keyPair = generateKeyPair();
  return { id, keyPair, signature: ed25519.sign(keyPair.publicKey, identity.privateKey) };
}

export function generateOneTimePreKeys(startId: number, count: number): OneTimePreKey[] {
  return Array.from({ length: count }, (_, i) => ({ id: startId + i, keyPair: generateKeyPair() }));
}

export function verifySignedPreKey(identityPublic: Uint8Array, preKeyPublic: Uint8Array, signature: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, preKeyPublic, identityPublic);
  } catch {
    return false;
  }
}

/** Chave privada X25519 correspondente à identidade Ed25519. */
export function identityDHPrivate(identity: IdentityKeyPair): Uint8Array {
  return ed25519.utils.toMontgomerySecret(identity.privateKey);
}

/** Chave pública X25519 correspondente a uma identidade Ed25519. */
export function identityDHPublic(identityPublic: Uint8Array): Uint8Array {
  return ed25519.utils.toMontgomery(identityPublic);
}

/**
 * Diffie-Hellman X25519. Rejeita pontos de ordem baixa (resultado nulo),
 * impedindo que um par malicioso force um segredo conhecido.
 */
export function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}
