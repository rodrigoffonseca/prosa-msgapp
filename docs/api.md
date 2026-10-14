# API do servidor (v1)

- Base: `https://seu-servidor/v1`
- Corpo e respostas em JSON; campos binários em **base64**.
- Autenticação: `Authorization: Bearer <token>` (no WebSocket, também `?token=`).
- Erros: `{"error": "mensagem"}` com o status HTTP adequado.

## Cadastro e sessão

| Método | Rota | Corpo | Resposta |
| --- | --- | --- | --- |
| POST | `/auth/request-code` | `{phone}` | `202 {expires_in}` (+ `dev_code` só em desenvolvimento). `429` se pedir de novo em menos de 1 min |
| POST | `/auth/verify` | `{phone, code}` | `200 {token, user, new_account}` · `401` código inválido/expirado |
| POST | `/auth/logout` | — | `204` |

Telefones aceitos: E.164 (`+55 11 98765-4321`) ou nacional com DDD (`11987654321`, assume +55).

## Perfil e contatos

| Método | Rota | Corpo | Resposta |
| --- | --- | --- | --- |
| GET | `/me` | — | `User` |
| PATCH | `/me` | `{username?, display_name?}` | `User` · `409` nome em uso |
| DELETE | `/me` | — | `204` (apaga a conta e os dados) |
| GET | `/users/{id}` | — | `User` |
| GET | `/users/by-username/{username}` | — | `User` (aceita `@`) |
| POST | `/users/lookup-phone` | `{phone}` | `User` · limitado a 120/h por usuário |

`User = {id, username, display_name, created_at}`

Nome de usuário: 3–32 caracteres, começa com letra, `a-z 0-9 _ .`, sem diferenciar maiúsculas.

## Chaves (X3DH)

| Método | Rota | Corpo | Resposta |
| --- | --- | --- | --- |
| PUT | `/keys` | `{registration_id, identity_key, signed_prekey: {id, public_key, signature}, one_time_prekeys: [{id, public_key}]}` | `204` |
| POST | `/keys/one-time` | `{one_time_prekeys: [...]}` | `204` |
| GET | `/keys/count` | — | `{one_time_prekeys}` |
| GET | `/keys/{userId}` | — | `{user_id, registration_id, identity_key, signed_prekey, one_time_prekey?}` — consome uma *one-time prekey* |

Chaves públicas têm 32 bytes; assinaturas, 64. Máximo de 500 *one-time prekeys* guardadas.

## Mensagens

| Método | Rota | Corpo | Resposta |
| --- | --- | --- | --- |
| POST | `/messages` | `{messages: [{to, registration_id, ciphertext}]}` | `201 {messages: [{id, to, server_timestamp}]}` |
| GET | `/messages?limit=100` | — | `{envelopes: [{id, sender_id, group_id?, ciphertext, server_timestamp}]}` |
| POST | `/messages/ack` | `{ids: [...]}` | `204` (apaga os envelopes entregues) |
| GET | `/ws` | — | WebSocket |

- `ciphertext`: até 64 KiB.
- `410 {stale: [userId]}`: o `registration_id` não é o atual do destinatário (ele reinstalou o app). Refaça a sessão e reenvie.

### WebSocket

```
servidor → {"type": "ready"}
servidor → {"type": "envelope", "envelope": {...}}
cliente  → {"type": "ack", "ids": ["..."]}
```

Ao receber `ready`, o cliente busca o que estiver pendente com `GET /messages` (pode haver duplicatas com o WebSocket — deduplique pelo `id`).

## Grupos

| Método | Rota | Corpo | Quem | Resposta |
| --- | --- | --- | --- | --- |
| POST | `/groups` | `{name, members: [userId]}` | qualquer um | `201 Group` (criador vira admin) |
| GET | `/groups` | — | — | `{groups: [Group]}` |
| GET | `/groups/{id}` | — | membro | `Group` |
| PATCH | `/groups/{id}` | `{name}` | admin | `Group` |
| POST | `/groups/{id}/members` | `{user_ids}` | admin | `Group` |
| DELETE | `/groups/{id}/members/{userId}` | — | admin, ou o próprio (sair) | `204` |
| PUT | `/groups/{id}/members/{userId}/role` | `{role: "admin"\|"member"}` | admin | `Group` |
| POST | `/groups/{id}/messages` | igual a `/messages` | membro | `201` · `409 {members}` se a lista de destinatários não for exatamente os outros membros |

`Group = {id, name, created_by, created_at, members: [{user_id, role, joined_at}]}` — até 256 membros. Se o último admin sair, o membro mais antigo é promovido; se todos saírem, o grupo é apagado.

## Anexos

| Método | Rota | Corpo | Resposta |
| --- | --- | --- | --- |
| POST | `/attachments` | bytes cifrados (`application/octet-stream`) | `201 {id, size}` · `413` acima do limite (25 MiB) |
| GET | `/attachments/{id}` | — | bytes cifrados · `404` se expirado |
