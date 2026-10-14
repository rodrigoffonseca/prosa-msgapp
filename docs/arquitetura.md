# Arquitetura

> Para a visão funcional (capacidades, fluxos ponta a ponta) e a infraestrutura necessária para operar o serviço, veja [arquitetura-funcional.md](arquitetura-funcional.md).

## Visão geral

O Prosa tem três peças:

| Peça | Linguagem | Responsabilidade |
| --- | --- | --- |
| `server/` | Go | Cadastro por telefone, sessões, diretório de chaves públicas, grupos, fila de entrega (*store-and-forward*), anexos cifrados, WebSocket |
| `packages/crypto/` | TypeScript | X3DH, Double Ratchet, cifra de anexos, padding, número de segurança |
| `packages/client/` | TypeScript | SDK que os apps usam: junta API + criptografia + armazenamento local |

O servidor é propositalmente "burro": ele transporta bytes opacos. Toda a lógica de conteúdo (o que é texto, foto ou áudio; legenda; duração; qual grupo) vive **dentro** da mensagem cifrada, que só os aparelhos leem.

### Por que Go no servidor?

Binário único, consumo baixo de memória, ótimo para muitas conexões simultâneas (WebSocket) e fácil de auto-hospedar — inclusive numa VPS barata ou num servidor de prefeitura/universidade.

### Por que TypeScript nos clientes?

O app será em React Native (Android e iOS com um só código). As bibliotecas `@noble/*` são JavaScript puro, auditadas e funcionam em React Native, no navegador e no Node — o mesmo código criptográfico roda em todo lugar e é testado contra o servidor real.

## Fluxos

### Cadastro

1. App envia o telefone → `POST /v1/auth/request-code`.
2. Servidor normaliza para E.164 (`+5511987654321`), calcula `HMAC-SHA256(pepper, telefone)` e guarda só o HMAC + o hash do código (validade de 10 min, 5 tentativas).
3. Servidor envia o SMS pelo provedor configurado (webhook próprio — qualquer operadora/fornecedor nacional).
4. App envia o código → `POST /v1/auth/verify` → recebe um token de sessão (o servidor guarda só o SHA-256 do token).
5. App gera no aparelho: par de identidade (Ed25519), *signed prekey* (X25519, assinada) e 100 *one-time prekeys*, e publica as partes **públicas** em `PUT /v1/keys`, junto com um `registration_id` aleatório da instalação.
6. Usuário escolhe `@nome` e nome de exibição (`PATCH /v1/me`).

Cadastrar o mesmo número em outro aparelho (ou reinstalar) mantém a conta, nome de usuário e grupos, mas encerra o aparelho anterior: sessões, chaves e mensagens pendentes do aparelho antigo são apagadas.

### Mensagem 1:1

1. Se ainda não há sessão com o contato, o app baixa o pacote de chaves dele (`GET /v1/keys/{id}`, que consome uma *one-time prekey*) e executa o X3DH.
2. O conteúdo (JSON com tipo, texto, ponteiro de anexo etc.) é preenchido até múltiplo de 160 bytes e cifrado com o Double Ratchet.
3. `POST /v1/messages` com `{to, registration_id, ciphertext}`. Se o `registration_id` não for o atual do contato (ele reinstalou o app), o servidor responde **410** e o SDK refaz a sessão com as chaves novas — e avisa o app que a chave de segurança mudou.
4. O servidor grava o envelope e o empurra pelo WebSocket, se o destinatário estiver conectado.
5. O destinatário decifra e confirma (`ack`); só então o envelope é apagado do servidor. Envelopes nunca confirmados são apagados após o período de retenção (padrão: 30 dias).

### Foto e áudio

1. O app gera uma chave AES-256 aleatória só para aquele arquivo, cifra (AES-GCM) e envia os bytes cifrados para `POST /v1/attachments`.
2. A mensagem E2EE leva o ponteiro: `{id, key, digest, mime, size, width/height | durationMs}`.
3. O destinatário baixa, confere o SHA-256 e decifra. O servidor nunca vê a chave.

### Grupos

- O servidor conhece o grupo (ID, nome, membros, administradores) para controlar quem pode enviar e para quem.
- O envio é por *fan-out* no cliente: o remetente cifra uma cópia para cada membro usando a sessão 1:1 com ele, e manda todas numa requisição só (`POST /v1/groups/{id}/messages`).
- O servidor exige que os destinatários sejam **exatamente** os membros atuais (responde 409 com a lista correta se não forem), para que ninguém removido continue recebendo e ninguém fique de fora.
- Simples e seguro para grupos de até 256 pessoas. Para grupos grandes, o roteiro prevê *sender keys*.

## Modelo de dados (PostgreSQL)

| Tabela | Conteúdo |
| --- | --- |
| `users` | id, HMAC do telefone, @nome, nome de exibição |
| `otp_challenges` | desafios de verificação em andamento (hash do código) |
| `sessions` | SHA-256 dos tokens de sessão |
| `identity_keys`, `one_time_prekeys` | chaves **públicas** do X3DH e `registration_id` |
| `groups`, `group_members` | grupos e papéis (admin/membro) |
| `envelopes` | fila de mensagens cifradas aguardando entrega |
| `attachments` | registro dos anexos cifrados (tamanho e validade); os bytes ficam em disco |

## Escalando

O MVP roda em uma instância. Para várias instâncias atrás de um balanceador:

- trocar o `Hub` em memória (`server/internal/api/hub.go`) por Postgres `LISTEN/NOTIFY` ou outro barramento;
- trocar os limitadores de taxa em memória por armazenamento compartilhado;
- trocar o armazenamento de anexos em disco por um armazenamento de objetos compatível com S3 hospedado no Brasil (ex.: MinIO próprio).
