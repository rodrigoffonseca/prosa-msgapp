package store

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrTooSoon = errors.New("aguarde antes de solicitar um novo código")

type User struct {
	ID          uuid.UUID `json:"id"`
	Username    *string   `json:"username"`
	DisplayName *string   `json:"display_name"`
	CreatedAt   time.Time `json:"created_at"`
}

const userCols = `id, username, display_name, created_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.CreatedAt); err != nil {
		return nil, notFound(err)
	}
	return &u, nil
}

// PutOTP registra um desafio de verificação, substituindo o anterior, desde
// que o anterior tenha sido criado há mais de minInterval.
func (s *Store) PutOTP(ctx context.Context, phoneHash, codeHash []byte, ttl, minInterval time.Duration) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO otp_challenges (phone_hash, code_hash, expires_at)
		VALUES ($1, $2, now() + make_interval(secs => $3))
		ON CONFLICT (phone_hash) DO UPDATE
		   SET code_hash = EXCLUDED.code_hash, attempts = 0,
		       expires_at = EXCLUDED.expires_at, created_at = now()
		 WHERE otp_challenges.created_at < now() - make_interval(secs => $4)`,
		phoneHash, codeHash, ttl.Seconds(), minInterval.Seconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTooSoon
	}
	return nil
}

// CheckOTP valida o código. Cada tentativa errada é contabilizada e, após
// maxAttempts, o desafio é descartado. Um código correto só pode ser usado uma vez.
func (s *Store) CheckOTP(ctx context.Context, phoneHash, codeHash []byte, maxAttempts int) (bool, error) {
	ok := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var stored []byte
		var attempts int
		var expired bool
		err := tx.QueryRow(ctx, `
			SELECT code_hash, attempts, expires_at < now()
			  FROM otp_challenges WHERE phone_hash = $1 FOR UPDATE`, phoneHash).
			Scan(&stored, &attempts, &expired)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if expired || attempts >= maxAttempts {
			_, err = tx.Exec(ctx, `DELETE FROM otp_challenges WHERE phone_hash = $1`, phoneHash)
			return err
		}
		if subtle.ConstantTimeCompare(stored, codeHash) == 1 {
			ok = true
			_, err = tx.Exec(ctx, `DELETE FROM otp_challenges WHERE phone_hash = $1`, phoneHash)
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE otp_challenges SET attempts = attempts + 1 WHERE phone_hash = $1`, phoneHash)
		return err
	})
	return ok, err
}

// RegisterDevice cria a conta (se não existir) e abre uma sessão nova.
//
// No MVP cada conta tem um único aparelho: registrar o número novamente
// encerra as sessões anteriores e descarta chaves e mensagens pendentes do
// aparelho antigo (que não conseguiria mais decifrá-las de qualquer forma).
func (s *Store) RegisterDevice(ctx context.Context, phoneHash, tokenHash []byte) (user *User, isNew bool, err error) {
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO users (id, phone_hash) VALUES ($1, $2)
			ON CONFLICT (phone_hash) DO NOTHING
			RETURNING `+userCols, uuid.New(), phoneHash)
		u, err := scanUser(row)
		switch {
		case err == nil:
			isNew = true
		case errors.Is(err, ErrNotFound):
			u, err = scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE phone_hash = $1 FOR UPDATE`, phoneHash))
			if err != nil {
				return err
			}
			for _, q := range []string{
				`DELETE FROM sessions WHERE user_id = $1`,
				`DELETE FROM identity_keys WHERE user_id = $1`,
				`DELETE FROM one_time_prekeys WHERE user_id = $1`,
				`DELETE FROM envelopes WHERE recipient_id = $1`,
			} {
				if _, err := tx.Exec(ctx, q, u.ID); err != nil {
					return err
				}
			}
		default:
			return err
		}
		user = u
		_, err = tx.Exec(ctx, `INSERT INTO sessions (token_hash, user_id) VALUES ($1, $2)`, tokenHash, u.ID)
		return err
	})
	return user, isNew, err
}

func (s *Store) UserBySession(ctx context.Context, tokenHash []byte) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT u.id, u.username, u.display_name, u.created_at
		  FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = $1`, tokenHash))
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteUser apaga a conta e todos os dados associados (direito à
// eliminação, LGPD art. 18).
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

func (s *Store) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE username = $1`, username))
}

func (s *Store) GetUserByPhoneHash(ctx context.Context, phoneHash []byte) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE phone_hash = $1`, phoneHash))
}

// UpdateProfile altera os campos não nulos. Devolve ErrConflict se o nome de
// usuário já estiver em uso.
func (s *Store) UpdateProfile(ctx context.Context, id uuid.UUID, username, displayName *string) (*User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `
		UPDATE users SET username = COALESCE($2, username),
		                 display_name = COALESCE($3, display_name)
		 WHERE id = $1 RETURNING `+userCols, id, username, displayName))
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	return u, err
}
