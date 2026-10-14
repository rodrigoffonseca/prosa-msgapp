package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxOneTimePreKeys limita quantas chaves de uso único cada conta pode manter.
const MaxOneTimePreKeys = 500

var ErrTooManyKeys = errors.New("limite de chaves de uso único excedido")

type SignedPreKey struct {
	ID        int    `json:"id"`
	PublicKey []byte `json:"public_key"`
	Signature []byte `json:"signature"`
}

type PreKey struct {
	ID        int    `json:"id"`
	PublicKey []byte `json:"public_key"`
}

type PreKeyBundle struct {
	UserID         uuid.UUID    `json:"user_id"`
	RegistrationID int          `json:"registration_id"`
	IdentityKey    []byte       `json:"identity_key"`
	SignedPreKey   SignedPreKey `json:"signed_prekey"`
	OneTimePreKey  *PreKey      `json:"one_time_prekey,omitempty"`
}

// SetKeys publica a chave de identidade e a signed prekey. Se a chave de
// identidade mudar, as one-time prekeys antigas são descartadas.
func (s *Store) SetKeys(ctx context.Context, userID uuid.UUID, registrationID int, identityKey []byte, spk SignedPreKey, otks []PreKey) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var old []byte
		err := tx.QueryRow(ctx, `SELECT identity_key FROM identity_keys WHERE user_id = $1 FOR UPDATE`, userID).Scan(&old)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if old != nil && string(old) != string(identityKey) {
			if _, err := tx.Exec(ctx, `DELETE FROM one_time_prekeys WHERE user_id = $1`, userID); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO identity_keys (user_id, registration_id, identity_key, signed_prekey_id, signed_prekey, signed_prekey_signature)
			VALUES ($1, $6, $2, $3, $4, $5)
			ON CONFLICT (user_id) DO UPDATE SET
			    registration_id = EXCLUDED.registration_id,
			    identity_key = EXCLUDED.identity_key,
			    signed_prekey_id = EXCLUDED.signed_prekey_id,
			    signed_prekey = EXCLUDED.signed_prekey,
			    signed_prekey_signature = EXCLUDED.signed_prekey_signature,
			    updated_at = now()`,
			userID, identityKey, spk.ID, spk.PublicKey, spk.Signature, registrationID)
		if err != nil {
			return err
		}
		return addOneTimePreKeys(ctx, tx, userID, otks)
	})
}

func (s *Store) AddOneTimePreKeys(ctx context.Context, userID uuid.UUID, otks []PreKey) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return addOneTimePreKeys(ctx, tx, userID, otks)
	})
}

func addOneTimePreKeys(ctx context.Context, tx pgx.Tx, userID uuid.UUID, otks []PreKey) error {
	if len(otks) == 0 {
		return nil
	}
	var batch pgx.Batch
	for _, k := range otks {
		batch.Queue(`INSERT INTO one_time_prekeys (user_id, key_id, public_key) VALUES ($1, $2, $3)
		             ON CONFLICT (user_id, key_id) DO UPDATE SET public_key = EXCLUDED.public_key`,
			userID, k.ID, k.PublicKey)
	}
	if err := tx.SendBatch(ctx, &batch).Close(); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM one_time_prekeys WHERE user_id = $1`, userID).Scan(&n); err != nil {
		return err
	}
	if n > MaxOneTimePreKeys {
		return ErrTooManyKeys
	}
	return nil
}

func (s *Store) CountOneTimePreKeys(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM one_time_prekeys WHERE user_id = $1`, userID).Scan(&n)
	return n, err
}

// TakePreKeyBundle devolve o pacote de chaves para iniciar uma sessão com o
// usuário, consumindo (apagando) uma one-time prekey, se houver.
func (s *Store) TakePreKeyBundle(ctx context.Context, userID uuid.UUID) (*PreKeyBundle, error) {
	b := &PreKeyBundle{UserID: userID}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT registration_id, identity_key, signed_prekey_id, signed_prekey, signed_prekey_signature
			  FROM identity_keys WHERE user_id = $1`, userID).
			Scan(&b.RegistrationID, &b.IdentityKey, &b.SignedPreKey.ID, &b.SignedPreKey.PublicKey, &b.SignedPreKey.Signature)
		if err != nil {
			return notFound(err)
		}
		var k PreKey
		err = tx.QueryRow(ctx, `
			DELETE FROM one_time_prekeys
			 WHERE (user_id, key_id) = (
			       SELECT user_id, key_id FROM one_time_prekeys
			        WHERE user_id = $1 ORDER BY key_id LIMIT 1
			          FOR UPDATE SKIP LOCKED)
			RETURNING key_id, public_key`, userID).Scan(&k.ID, &k.PublicKey)
		switch {
		case err == nil:
			b.OneTimePreKey = &k
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return b, nil
}

// RegistrationIDs devolve o registration_id atual de cada usuário que tem
// chaves publicadas.
func (s *Store) RegistrationIDs(ctx context.Context, userIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT user_id, registration_id FROM identity_keys WHERE user_id = ANY($1)`, userIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[uuid.UUID]int, len(userIDs))
	for rows.Next() {
		var id uuid.UUID
		var reg int
		if err := rows.Scan(&id, &reg); err != nil {
			return nil, err
		}
		out[id] = reg
	}
	return out, rows.Err()
}
