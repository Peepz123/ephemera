-- ephemera relay schema, PROTOCOL.md section 10.
--
-- Nothing in this schema is readable by the operator in any useful sense.
-- `envelopes.body` and blob objects are ciphertext; the server holds no key
-- that decrypts either.

CREATE TABLE accounts (
    id          UUID PRIMARY KEY,
    username    TEXT        NOT NULL UNIQUE,
    ik_sig      BYTEA       NOT NULL,
    ik_dh       BYTEA       NOT NULL,
    ik_dh_sig   BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT ik_sig_len    CHECK (octet_length(ik_sig)    = 32),
    CONSTRAINT ik_dh_len     CHECK (octet_length(ik_dh)     = 32),
    CONSTRAINT ik_dh_sig_len CHECK (octet_length(ik_dh_sig) = 64),
    CONSTRAINT username_fmt  CHECK (username ~ '^[a-z0-9_.-]{3,32}$')
);

-- Signed prekeys. The previous generation is retained for 7 days (3.2), so
-- an account may hold more than one row at a time.
CREATE TABLE signed_prekeys (
    account_id  UUID        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    spk_id      BIGINT      NOT NULL,
    spk_pub     BYTEA       NOT NULL,
    spk_sig     BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (account_id, spk_id),
    CONSTRAINT spk_pub_len CHECK (octet_length(spk_pub) = 32),
    CONSTRAINT spk_sig_len CHECK (octet_length(spk_sig) = 64)
);

-- One-time prekeys. Deleted on issue, never reissued (3.2, T-3).
--
-- Rows are deleted rather than flagged: a consumed OPK has no further use and
-- retaining it would only widen what an operator or a subpoena could see.
CREATE TABLE one_time_prekeys (
    account_id  UUID        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    opk_id      BIGINT      NOT NULL,
    opk_pub     BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (account_id, opk_id),
    CONSTRAINT opk_pub_len CHECK (octet_length(opk_pub) = 32)
);

CREATE INDEX one_time_prekeys_account ON one_time_prekeys (account_id);

-- Store-and-forward queue. Rows are deleted on delivery acknowledgement;
-- retention past that point is zero (T-19).
CREATE TABLE envelopes (
    id            UUID        PRIMARY KEY,
    recipient_id  UUID        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    body          BYTEA       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT body_size CHECK (octet_length(body) <= 65536)
);

CREATE INDEX envelopes_recipient ON envelopes (recipient_id, created_at);

-- Attachment blobs. `state` is the enforcement point for one-view retrieval,
-- not the lifetime of the stored object (8.1, T-10).
CREATE TYPE blob_state AS ENUM ('unread', 'consumed');

CREATE TABLE blobs (
    blob_id      BYTEA       PRIMARY KEY,
    recipient_id UUID        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    storage_key  TEXT        NOT NULL,
    one_view     BOOLEAN     NOT NULL,
    state        blob_state  NOT NULL DEFAULT 'unread',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at  TIMESTAMPTZ,

    CONSTRAINT blob_id_len CHECK (octet_length(blob_id) = 32)
);

-- Short-lived authentication challenges. A client proves control of IK_sig by
-- signing one of these; no password exists anywhere in the system (10).
CREATE TABLE auth_challenges (
    nonce       BYTEA       PRIMARY KEY,
    username    TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,

    CONSTRAINT nonce_len CHECK (octet_length(nonce) = 32)
);

CREATE INDEX auth_challenges_expiry ON auth_challenges (expires_at);
