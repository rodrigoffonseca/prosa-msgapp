import { describe, expect, it } from 'vitest';

import {
  InMemoryProtocolStore,
  type PreKeyBundle,
  decrypt,
  decryptAttachment,
  encrypt,
  encryptAttachment,
  fromBase64,
  generateIdentityKeyPair,
  generateOneTimePreKeys,
  generateSignedPreKey,
  initiateSession,
  pad,
  safetyNumber,
  toBase64,
  unpad,
  utf8,
} from '../src/index.js';

function party(withOneTime = true) {
  const store = new InMemoryProtocolStore(generateIdentityKeyPair());
  const spk = generateSignedPreKey(store.identity, 1);
  store.addSignedPreKey(spk);
  const otks = generateOneTimePreKeys(1, 5);
  store.addOneTimePreKeys(otks);
  const bundle = (): PreKeyBundle => {
    const otk = withOneTime ? otks.find((k) => store.oneTimePreKeys.has(k.id)) : undefined;
    return {
      identityKey: store.identity.publicKey,
      signedPreKey: { id: spk.id, publicKey: spk.keyPair.publicKey, signature: spk.signature },
      oneTimePreKey: otk && { id: otk.id, publicKey: otk.keyPair.publicKey },
    };
  };
  return { store, bundle };
}

const t = (s: string) => utf8.encode(s);
const s = (b: Uint8Array) => utf8.decode(b);

describe('sessão 1:1', () => {
  it('troca mensagens nos dois sentidos', async () => {
    const alice = party();
    const bob = party();
    await initiateSession(alice.store, 'bob', bob.bundle());

    const m1 = await encrypt(alice.store, 'bob', t('Oi, Bob!'));
    const r1 = await decrypt(bob.store, 'alice', m1);
    expect(s(r1.plaintext)).toBe('Oi, Bob!');
    expect(r1.newSession).toBe(true);
    expect(r1.remoteIdentity).toEqual(alice.store.identity.publicKey);
    // One-time prekey consumida.
    expect(bob.store.oneTimePreKeys.size).toBe(4);

    for (let i = 0; i < 5; i++) {
      const a = await encrypt(bob.store, 'alice', t(`resposta ${i}`));
      expect(s((await decrypt(alice.store, 'bob', a)).plaintext)).toBe(`resposta ${i}`);
      const b = await encrypt(alice.store, 'bob', t(`pergunta ${i}`));
      expect(b[1]).toBe(2); // já não é PreKey message
      expect(s((await decrypt(bob.store, 'alice', b)).plaintext)).toBe(`pergunta ${i}`);
    }
  });

  it('funciona sem one-time prekey', async () => {
    const alice = party();
    const bob = party(false);
    await initiateSession(alice.store, 'bob', bob.bundle());
    const m = await encrypt(alice.store, 'bob', t('sem otk'));
    expect(s((await decrypt(bob.store, 'alice', m)).plaintext)).toBe('sem otk');
  });

  it('continua enviando PreKey messages até receber resposta', async () => {
    const alice = party();
    const bob = party();
    await initiateSession(alice.store, 'bob', bob.bundle());
    const m1 = await encrypt(alice.store, 'bob', t('1'));
    const m2 = await encrypt(alice.store, 'bob', t('2'));
    expect(m2[1]).toBe(1);
    // Chegam fora de ordem.
    expect(s((await decrypt(bob.store, 'alice', m2)).plaintext)).toBe('2');
    const r1 = await decrypt(bob.store, 'alice', m1);
    expect(s(r1.plaintext)).toBe('1');
    expect(r1.newSession).toBe(false);
  });

  it('decifra mensagens fora de ordem e perdidas', async () => {
    const alice = party();
    const bob = party();
    await initiateSession(alice.store, 'bob', bob.bundle());
    await decrypt(bob.store, 'alice', await encrypt(alice.store, 'bob', t('olá')));
    await decrypt(alice.store, 'bob', await encrypt(bob.store, 'alice', t('olá')));

    const msgs = [];
    for (let i = 0; i < 10; i++) msgs.push(await encrypt(alice.store, 'bob', t(`m${i}`)));
    for (const i of [9, 3, 0, 5]) {
      expect(s((await decrypt(bob.store, 'alice', msgs[i]!)).plaintext)).toBe(`m${i}`);
    }
    // Repetir uma mensagem já lida falha (chave já descartada).
    await expect(decrypt(bob.store, 'alice', msgs[3]!)).rejects.toThrow();
  });

  it('rejeita mensagem adulterada sem corromper a sessão', async () => {
    const alice = party();
    const bob = party();
    await initiateSession(alice.store, 'bob', bob.bundle());
    await decrypt(bob.store, 'alice', await encrypt(alice.store, 'bob', t('olá')));
    await decrypt(alice.store, 'bob', await encrypt(bob.store, 'alice', t('olá')));

    const m = await encrypt(alice.store, 'bob', t('segredo'));
    const forged = m.slice();
    forged[forged.length - 1]! ^= 1;
    await expect(decrypt(bob.store, 'alice', forged)).rejects.toThrow();
    expect(s((await decrypt(bob.store, 'alice', m)).plaintext)).toBe('segredo');
  });

  it('rejeita bundle com assinatura inválida', async () => {
    const alice = party();
    const bob = party();
    const bundle = bob.bundle();
    bundle.signedPreKey.signature = bundle.signedPreKey.signature.slice();
    bundle.signedPreKey.signature[0]! ^= 1;
    await expect(initiateSession(alice.store, 'bob', bundle)).rejects.toThrow(/assinatura/);
  });

  it('não aceita replay de PreKey message depois que a one-time prekey foi usada', async () => {
    const alice = party();
    const bob = party();
    await initiateSession(alice.store, 'bob', bob.bundle());
    const m = await encrypt(alice.store, 'bob', t('uma vez'));
    await decrypt(bob.store, 'alice', m);
    bob.store.sessions.clear(); // simula atacante reenviando após perda de estado
    await expect(decrypt(bob.store, 'alice', m)).rejects.toThrow(/one-time prekey/);
  });

  it('converge quando os dois iniciam a sessão ao mesmo tempo', async () => {
    const alice = party();
    const bob = party();
    await initiateSession(alice.store, 'bob', bob.bundle());
    await initiateSession(bob.store, 'alice', alice.bundle());
    const fromAlice = await encrypt(alice.store, 'bob', t('a1'));
    const fromBob = await encrypt(bob.store, 'alice', t('b1'));
    expect(s((await decrypt(bob.store, 'alice', fromAlice)).plaintext)).toBe('a1');
    expect(s((await decrypt(alice.store, 'bob', fromBob)).plaintext)).toBe('b1');
    for (let i = 0; i < 3; i++) {
      expect(s((await decrypt(bob.store, 'alice', await encrypt(alice.store, 'bob', t(`a${i}`)))).plaintext)).toBe(`a${i}`);
      expect(s((await decrypt(alice.store, 'bob', await encrypt(bob.store, 'alice', t(`b${i}`)))).plaintext)).toBe(`b${i}`);
    }
  });

  it('a sessão sobrevive à serialização', async () => {
    const alice = party();
    const bob = party();
    await initiateSession(alice.store, 'bob', bob.bundle());
    await decrypt(bob.store, 'alice', await encrypt(alice.store, 'bob', t('x')));
    const raw = bob.store.sessions.get('alice')!;
    bob.store.sessions.set('alice', JSON.parse(JSON.stringify(raw)));
    const m = await encrypt(bob.store, 'alice', t('depois de reiniciar'));
    expect(s((await decrypt(alice.store, 'bob', m)).plaintext)).toBe('depois de reiniciar');
  });
});

describe('anexos', () => {
  it('cifra e decifra', () => {
    const data = new Uint8Array(100_000).map((_, i) => i % 251);
    const enc = encryptAttachment(data);
    expect(decryptAttachment(enc.ciphertext, enc.key, enc.digest)).toEqual(data);
  });

  it('detecta adulteração', () => {
    const enc = encryptAttachment(new Uint8Array([1, 2, 3]));
    const bad = enc.ciphertext.slice();
    bad[20]! ^= 1;
    expect(() => decryptAttachment(bad, enc.key, enc.digest)).toThrow(/adulterado/);
  });
});

describe('utilitários', () => {
  it('padding esconde o tamanho', () => {
    expect(pad(t('oi')).length).toBe(160);
    expect(pad(new Uint8Array(159)).length).toBe(160);
    expect(pad(new Uint8Array(160)).length).toBe(320);
    expect(unpad(pad(t('olá')))).toEqual(t('olá'));
    const zeros = new Uint8Array([1, 0, 0]);
    expect(unpad(pad(zeros))).toEqual(zeros);
  });

  it('base64 compatível com o padrão', () => {
    for (const n of [0, 1, 2, 3, 4, 31, 32, 33]) {
      const b = new Uint8Array(n).map((_, i) => (i * 37) & 0xff);
      expect(toBase64(b)).toBe(Buffer.from(b).toString('base64'));
      expect(fromBase64(toBase64(b))).toEqual(b);
    }
  });

  it('número de segurança é igual para os dois lados', () => {
    const a = generateIdentityKeyPair().publicKey;
    const b = generateIdentityKeyPair().publicKey;
    const n = safetyNumber(a, 'alice', b, 'bob');
    expect(n).toMatch(/^\d{60}$/);
    expect(safetyNumber(b, 'bob', a, 'alice')).toBe(n);
    expect(safetyNumber(generateIdentityKeyPair().publicKey, 'alice', b, 'bob')).not.toBe(n);
  });
});
