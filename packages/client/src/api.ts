// Cliente HTTP da API do servidor Prosa. Campos binários trafegam em base64.

import { fromBase64, toBase64 } from '@prosa/crypto';

export interface User {
  id: string;
  username: string | null;
  display_name: string | null;
  created_at: string;
}

export interface GroupMember {
  user_id: string;
  role: 'admin' | 'member';
  joined_at: string;
}

export interface Group {
  id: string;
  name: string;
  created_by: string | null;
  created_at: string;
  members: GroupMember[];
}

export interface Envelope {
  id: string;
  sender_id: string;
  group_id?: string;
  ciphertext: Uint8Array;
  server_timestamp: string;
}

export interface RemoteBundle {
  user_id: string;
  registration_id: number;
  identity_key: Uint8Array;
  signed_prekey: { id: number; public_key: Uint8Array; signature: Uint8Array };
  one_time_prekey?: { id: number; public_key: Uint8Array };
}

export interface OutgoingMessage {
  to: string;
  registrationId: number;
  ciphertext: Uint8Array;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export class Api {
  token: string | undefined;

  constructor(readonly baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  async request<T>(method: string, path: string, body?: unknown, raw?: Uint8Array): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    let payload: BodyInit | undefined;
    if (raw) {
      headers['Content-Type'] = 'application/octet-stream';
      payload = raw as unknown as BodyInit;
    } else if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }
    const res = await fetch(this.baseUrl + path, { method, headers, body: payload });
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    const data = text ? JSON.parse(text) : {};
    if (!res.ok) throw new ApiError(res.status, data.error ?? res.statusText, data);
    return data as T;
  }

  requestCode(phone: string) {
    return this.request<{ expires_in: number; dev_code?: string }>('POST', '/v1/auth/request-code', { phone });
  }

  verify(phone: string, code: string) {
    return this.request<{ token: string; user: User; new_account: boolean }>('POST', '/v1/auth/verify', { phone, code });
  }

  logout() {
    return this.request<void>('POST', '/v1/auth/logout');
  }

  me() {
    return this.request<User>('GET', '/v1/me');
  }

  updateMe(fields: { username?: string; display_name?: string }) {
    return this.request<User>('PATCH', '/v1/me', fields);
  }

  deleteMe() {
    return this.request<void>('DELETE', '/v1/me');
  }

  getUser(id: string) {
    return this.request<User>('GET', `/v1/users/${encodeURIComponent(id)}`);
  }

  getUserByUsername(username: string) {
    return this.request<User>('GET', `/v1/users/by-username/${encodeURIComponent(username)}`);
  }

  lookupPhone(phone: string) {
    return this.request<User>('POST', '/v1/users/lookup-phone', { phone });
  }

  putKeys(keys: {
    registrationId: number;
    identityKey: Uint8Array;
    signedPreKey: { id: number; publicKey: Uint8Array; signature: Uint8Array };
    oneTimePreKeys: { id: number; publicKey: Uint8Array }[];
  }) {
    return this.request<void>('PUT', '/v1/keys', {
      registration_id: keys.registrationId,
      identity_key: toBase64(keys.identityKey),
      signed_prekey: {
        id: keys.signedPreKey.id,
        public_key: toBase64(keys.signedPreKey.publicKey),
        signature: toBase64(keys.signedPreKey.signature),
      },
      one_time_prekeys: keys.oneTimePreKeys.map((k) => ({ id: k.id, public_key: toBase64(k.publicKey) })),
    });
  }

  addOneTimePreKeys(keys: { id: number; publicKey: Uint8Array }[]) {
    return this.request<void>('POST', '/v1/keys/one-time', {
      one_time_prekeys: keys.map((k) => ({ id: k.id, public_key: toBase64(k.publicKey) })),
    });
  }

  async countOneTimePreKeys(): Promise<number> {
    return (await this.request<{ one_time_prekeys: number }>('GET', '/v1/keys/count')).one_time_prekeys;
  }

  async getBundle(userId: string): Promise<RemoteBundle> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const b = await this.request<any>('GET', `/v1/keys/${encodeURIComponent(userId)}`);
    return {
      user_id: b.user_id,
      registration_id: b.registration_id,
      identity_key: fromBase64(b.identity_key),
      signed_prekey: {
        id: b.signed_prekey.id,
        public_key: fromBase64(b.signed_prekey.public_key),
        signature: fromBase64(b.signed_prekey.signature),
      },
      one_time_prekey: b.one_time_prekey && {
        id: b.one_time_prekey.id,
        public_key: fromBase64(b.one_time_prekey.public_key),
      },
    };
  }

  /**
   * Envia mensagens já cifradas. Lança ApiError 410 com body.stale (IDs) se
   * algum destinatário reinstalou o app, e 409 com body.members se a lista
   * de um grupo estiver desatualizada.
   */
  sendMessages(groupId: string | undefined, messages: OutgoingMessage[]) {
    const path = groupId ? `/v1/groups/${encodeURIComponent(groupId)}/messages` : '/v1/messages';
    return this.request<{ messages: { id: string; to: string; server_timestamp: string }[] }>('POST', path, {
      messages: messages.map((m) => ({
        to: m.to,
        registration_id: m.registrationId,
        ciphertext: toBase64(m.ciphertext),
      })),
    });
  }

  async pendingEnvelopes(limit = 100): Promise<Envelope[]> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const r = await this.request<{ envelopes: any[] }>('GET', `/v1/messages?limit=${limit}`);
    return r.envelopes.map(parseEnvelope);
  }

  ack(ids: string[]) {
    return this.request<void>('POST', '/v1/messages/ack', { ids });
  }

  createGroup(name: string, members: string[]) {
    return this.request<Group>('POST', '/v1/groups', { name, members });
  }

  async listGroups(): Promise<Group[]> {
    return (await this.request<{ groups: Group[] }>('GET', '/v1/groups')).groups;
  }

  getGroup(id: string) {
    return this.request<Group>('GET', `/v1/groups/${encodeURIComponent(id)}`);
  }

  renameGroup(id: string, name: string) {
    return this.request<Group>('PATCH', `/v1/groups/${encodeURIComponent(id)}`, { name });
  }

  addGroupMembers(id: string, userIds: string[]) {
    return this.request<Group>('POST', `/v1/groups/${encodeURIComponent(id)}/members`, { user_ids: userIds });
  }

  removeGroupMember(id: string, userId: string) {
    return this.request<void>('DELETE', `/v1/groups/${encodeURIComponent(id)}/members/${encodeURIComponent(userId)}`);
  }

  setGroupRole(id: string, userId: string, role: 'admin' | 'member') {
    return this.request<Group>(
      'PUT',
      `/v1/groups/${encodeURIComponent(id)}/members/${encodeURIComponent(userId)}/role`,
      { role },
    );
  }

  uploadAttachment(ciphertext: Uint8Array) {
    return this.request<{ id: string; size: number }>('POST', '/v1/attachments', undefined, ciphertext);
  }

  async downloadAttachment(id: string): Promise<Uint8Array> {
    const res = await fetch(`${this.baseUrl}/v1/attachments/${encodeURIComponent(id)}`, {
      headers: this.token ? { Authorization: `Bearer ${this.token}` } : {},
    });
    if (!res.ok) throw new ApiError(res.status, 'falha ao baixar anexo');
    return new Uint8Array(await res.arrayBuffer());
  }

  webSocketUrl(): string {
    return `${this.baseUrl.replace(/^http/, 'ws')}/v1/ws?token=${encodeURIComponent(this.token ?? '')}`;
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseEnvelope(e: any): Envelope {
  return { ...e, ciphertext: fromBase64(e.ciphertext) };
}
