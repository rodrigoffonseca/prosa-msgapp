-- Esquema inicial do Prosa.
-- Princípio: o servidor guarda o mínimo necessário para entregar mensagens.
-- Conteúdo de mensagens e anexos é sempre cifrado de ponta a ponta pelo cliente.

CREATE TABLE users (
    id           UUID PRIMARY KEY,
    -- HMAC-SHA256(pepper, telefone E.164). O número em claro nunca é salvo.
    phone_hash   BYTEA NOT NULL UNIQUE,
    username     TEXT UNIQUE,
    display_name TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE otp_challenges (
    phone_hash BYTEA PRIMARY KEY,
    code_hash  BYTEA NOT NULL,
    attempts   INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    -- SHA-256 do token; o token em si só existe no aparelho.
    token_hash BYTEA PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

-- Chaves públicas do protocolo X3DH. As chaves privadas nunca saem do aparelho.
CREATE TABLE identity_keys (
    user_id                  UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- Número aleatório gerado a cada instalação do app. Remetentes informam o
    -- registration_id que conhecem; se divergir, a sessão está desatualizada.
    registration_id          INT NOT NULL,
    identity_key             BYTEA NOT NULL,
    signed_prekey_id         INT NOT NULL,
    signed_prekey            BYTEA NOT NULL,
    signed_prekey_signature  BYTEA NOT NULL,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE one_time_prekeys (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id     INT NOT NULL,
    public_key BYTEA NOT NULL,
    PRIMARY KEY (user_id, key_id)
);

CREATE TABLE groups (
    id         UUID PRIMARY KEY,
    name       TEXT NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE group_members (
    group_id  UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role      TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user_idx ON group_members(user_id);

-- Fila de entrega (store-and-forward). Envelopes são apagados assim que o
-- destinatário confirma o recebimento, ou após o período de retenção.
CREATE TABLE envelopes (
    id           UUID PRIMARY KEY,
    recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id     UUID REFERENCES groups(id) ON DELETE SET NULL,
    ciphertext   BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX envelopes_recipient_idx ON envelopes(recipient_id, created_at);

-- Anexos cifrados (fotos, áudios). O servidor só vê bytes opacos e o tamanho.
CREATE TABLE attachments (
    id          UUID PRIMARY KEY,
    uploader_id UUID REFERENCES users(id) ON DELETE SET NULL,
    size_bytes  BIGINT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX attachments_expires_idx ON attachments(expires_at);
