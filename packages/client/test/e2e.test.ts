// Teste ponta a ponta: sobe o servidor Go de verdade (com PostgreSQL) e faz
// três clientes conversarem com texto, foto, áudio e grupo.
//
//   PROSA_TEST_DATABASE_URL=postgres://... npm test -w @prosa/client

import { type ChildProcess, execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { KeyValueStorage, ProsaClient, type ReceivedMessage } from '../src/index.js';

const dbUrl = process.env.PROSA_TEST_DATABASE_URL;
const serverDir = fileURLToPath(new URL('../../../server', import.meta.url));

let server: ChildProcess | undefined;
let baseUrl = '';
let tmp = '';

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
  });
}

let phoneSeq = Date.now() % 10_000_000;

async function newUser(name: string) {
  const client = new ProsaClient({ serverUrl: baseUrl, storage: new KeyValueStorage() });
  const phone = `+5511 9${String(++phoneSeq).padStart(8, '0')}`;
  const { dev_code } = await client.requestCode(phone);
  const { user } = await client.verifyCode(phone, dev_code!);
  await client.setProfile({ username: `${name}${phoneSeq}`, displayName: name });
  const inbox: ReceivedMessage[] = [];
  client.on('message', (m) => inbox.push(m));
  return { client, user, inbox, phone, username: `${name}${phoneSeq}` };
}

async function waitFor<T>(fn: () => T | undefined, ms = 10_000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = fn();
    if (v !== undefined) return v;
    if (Date.now() > end) throw new Error('tempo esgotado');
    await new Promise((r) => setTimeout(r, 25));
  }
}

describe.skipIf(!dbUrl)('ponta a ponta com o servidor', () => {
  beforeAll(async () => {
    tmp = mkdtempSync(join(tmpdir(), 'prosa-e2e-'));
    const bin = join(tmp, 'prosa-server');
    execFileSync('go', ['build', '-o', bin, './cmd/prosa-server'], { cwd: serverDir, stdio: 'inherit' });
    const port = await freePort();
    baseUrl = `http://127.0.0.1:${port}`;
    server = spawn(bin, [], {
      env: {
        ...process.env,
        PROSA_ENV: 'development',
        PROSA_LISTEN_ADDR: `127.0.0.1:${port}`,
        PROSA_DATABASE_URL: dbUrl,
        PROSA_DEV_EXPOSE_OTP: 'true',
        PROSA_BLOB_DIR: join(tmp, 'blobs'),
      },
      stdio: ['ignore', 'ignore', 'inherit'],
    });
    await waitFor(() => undefined, 0).catch(() => undefined);
    const end = Date.now() + 20_000;
    for (;;) {
      try {
        if ((await fetch(`${baseUrl}/healthz`)).ok) break;
      } catch {
        /* ainda subindo */
      }
      if (Date.now() > end) throw new Error('servidor não subiu');
      await new Promise((r) => setTimeout(r, 100));
    }
  });

  afterAll(() => {
    server?.kill();
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  });

  it('texto, foto, áudio e grupo, sem o servidor ver o conteúdo', async () => {
    const alice = await newUser('alice');
    const bob = await newUser('bob');
    const carol = await newUser('carol');

    // Bob encontra a Alice pelo nome de usuário.
    const found = await bob.client.findByUsername('@' + alice.username);
    expect(found.id).toBe(alice.user.id);

    // Texto (Bob ainda offline: fica na fila do servidor).
    await alice.client.sendText({ userId: bob.user.id }, 'Oi Bob! Tudo bem? 🇧🇷');
    const pending = await bob.client.api.pendingEnvelopes();
    expect(pending).toHaveLength(1);
    expect(new TextDecoder().decode(pending[0]!.ciphertext)).not.toContain('Oi Bob');
    await bob.client.sync();
    expect(bob.inbox[0]).toMatchObject({ kind: 'text', text: 'Oi Bob! Tudo bem? 🇧🇷', from: alice.user.id });
    expect(await bob.client.api.pendingEnvelopes()).toHaveLength(0);

    // Tempo real via WebSocket.
    alice.client.connect();
    bob.client.connect();
    carol.client.connect();
    await new Promise((r) => setTimeout(r, 300));

    await bob.client.sendText({ userId: alice.user.id }, 'Tudo ótimo!');
    const reply = await waitFor(() => alice.inbox.find((m) => m.text === 'Tudo ótimo!'));
    expect(reply.from).toBe(bob.user.id);

    // Foto.
    const photo = new Uint8Array(200_000).map((_, i) => (i * 7) % 256);
    await alice.client.sendImage({ userId: bob.user.id }, photo, { mime: 'image/jpeg', width: 800, height: 600, caption: 'praia' });
    const img = await waitFor(() => bob.inbox.find((m) => m.kind === 'image'));
    expect(img.text).toBe('praia');
    expect(img.attachment).toMatchObject({ mime: 'image/jpeg', width: 800, height: 600, size: photo.length });
    expect(await bob.client.downloadAttachment(img.attachment!)).toEqual(photo);
    // O que está no servidor é cifrado.
    const stored = await bob.client.api.downloadAttachment(img.attachment!.id);
    expect(stored).not.toEqual(photo);

    // Áudio.
    const voice = new Uint8Array(30_000).map((_, i) => (i * 13) % 256);
    await bob.client.sendVoice({ userId: alice.user.id }, voice, { mime: 'audio/ogg; codecs=opus', durationMs: 4200 });
    const audio = await waitFor(() => alice.inbox.find((m) => m.kind === 'voice'));
    expect(audio.attachment!.durationMs).toBe(4200);
    expect(await alice.client.downloadAttachment(audio.attachment!)).toEqual(voice);

    // Grupo.
    const group = await alice.client.createGroup('Churrasco de domingo', [bob.user.id, carol.user.id]);
    await alice.client.sendText({ groupId: group.id }, 'Quem leva o carvão?');
    for (const u of [bob, carol]) {
      const m = await waitFor(() => u.inbox.find((x) => x.groupId === group.id));
      expect(m).toMatchObject({ text: 'Quem leva o carvão?', from: alice.user.id });
    }
    await carol.client.sendVoice({ groupId: group.id }, voice, { mime: 'audio/ogg', durationMs: 1000 });
    await waitFor(() => alice.inbox.find((x) => x.groupId === group.id && x.kind === 'voice'));
    await waitFor(() => bob.inbox.find((x) => x.groupId === group.id && x.kind === 'voice'));

    // Bob sai; a próxima mensagem não chega para ele.
    await bob.client.leaveGroup(group.id);
    await alice.client.sendText({ groupId: group.id }, 'Bob saiu');
    await waitFor(() => carol.inbox.find((x) => x.text === 'Bob saiu'));
    await new Promise((r) => setTimeout(r, 200));
    expect(bob.inbox.find((x) => x.text === 'Bob saiu')).toBeUndefined();

    // Número de segurança idêntico dos dois lados.
    expect(await alice.client.safetyNumber(bob.user.id)).toBe(await bob.client.safetyNumber(alice.user.id));

    for (const u of [alice, bob, carol]) u.client.disconnect();
  });

  it('refaz a sessão e avisa quando o contato reinstala o app', async () => {
    const alice = await newUser('ana');
    const bob = await newUser('beto');
    await alice.client.sendText({ userId: bob.user.id }, 'oi');
    await bob.client.sync();
    await bob.client.sendText({ userId: alice.user.id }, 'oi, Ana');
    await alice.client.sync();
    const before = await alice.client.safetyNumber(bob.user.id);

    // Bob reinstala o app: mesmo número, aparelho novo, chaves novas.
    const bob2 = new ProsaClient({ serverUrl: baseUrl, storage: new KeyValueStorage() });
    const { dev_code } = await bob2.requestCode(bob.phone);
    await bob2.verifyCode(bob.phone, dev_code!);
    expect(bob2.currentUserId).toBe(bob.user.id);
    const inbox2: ReceivedMessage[] = [];
    bob2.on('message', (m) => inbox2.push(m));

    const changes: string[] = [];
    alice.client.on('identityChanged', (c) => changes.push(c.userId));
    // Alice ainda tem a sessão antiga; o servidor recusa (410) e o cliente
    // refaz a sessão com as chaves novas automaticamente.
    await alice.client.sendText({ userId: bob.user.id }, 'você trocou de celular?');
    expect(changes).toEqual([bob.user.id]);
    expect(await alice.client.safetyNumber(bob.user.id)).not.toBe(before);

    await bob2.sync();
    expect(inbox2.map((m) => m.text)).toEqual(['você trocou de celular?']);
    await bob2.sendText({ userId: alice.user.id }, 'troquei sim');
    await alice.client.sync();
    expect(alice.inbox.at(-1)?.text).toBe('troquei sim');
  });

  it('com a política "reject", não envia para quem trocou de chave sem confirmação', async () => {
    const strict = new ProsaClient({ serverUrl: baseUrl, storage: new KeyValueStorage(), identityChangePolicy: 'reject' });
    const phone = `+5511 9${String(++phoneSeq).padStart(8, '0')}`;
    await strict.verifyCode(phone, (await strict.requestCode(phone)).dev_code!);
    const bob = await newUser('bia');
    await strict.sendText({ userId: bob.user.id }, 'oi');

    const bob2 = new ProsaClient({ serverUrl: baseUrl, storage: new KeyValueStorage() });
    await bob2.verifyCode(bob.phone, (await bob2.requestCode(bob.phone)).dev_code!);
    await expect(strict.sendText({ userId: bob.user.id }, 'oi de novo')).rejects.toThrow(/mudou/);
  });
});
