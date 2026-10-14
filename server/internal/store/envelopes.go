package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Envelope é uma mensagem cifrada aguardando entrega. O servidor não tem
// como ler Ciphertext.
type Envelope struct {
	ID          uuid.UUID  `json:"id"`
	RecipientID uuid.UUID  `json:"-"`
	SenderID    uuid.UUID  `json:"sender_id"`
	GroupID     *uuid.UUID `json:"group_id,omitempty"`
	Ciphertext  []byte     `json:"ciphertext"`
	CreatedAt   time.Time  `json:"server_timestamp"`
}

// InsertEnvelopes grava os envelopes atomicamente, preenchendo ID e CreatedAt.
func (s *Store) InsertEnvelopes(ctx context.Context, envs []*Envelope) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for _, e := range envs {
			e.ID = uuid.New()
			err := tx.QueryRow(ctx, `
				INSERT INTO envelopes (id, recipient_id, sender_id, group_id, ciphertext)
				VALUES ($1, $2, $3, $4, $5) RETURNING created_at`,
				e.ID, e.RecipientID, e.SenderID, e.GroupID, e.Ciphertext).Scan(&e.CreatedAt)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) PendingEnvelopes(ctx context.Context, recipient uuid.UUID, limit int) ([]*Envelope, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, recipient_id, sender_id, group_id, ciphertext, created_at
		  FROM envelopes WHERE recipient_id = $1
		 ORDER BY created_at, id LIMIT $2`, recipient, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (*Envelope, error) {
		var e Envelope
		err := r.Scan(&e.ID, &e.RecipientID, &e.SenderID, &e.GroupID, &e.Ciphertext, &e.CreatedAt)
		return &e, err
	})
}

// AckEnvelopes apaga envelopes entregues. Só apaga os do próprio destinatário.
func (s *Store) AckEnvelopes(ctx context.Context, recipient uuid.UUID, ids []uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM envelopes WHERE recipient_id = $1 AND id = ANY($2)`, recipient, ids)
	return err
}

// PurgeExpired remove envelopes não entregues e registros de anexos mais
// antigos que o período de retenção. Devolve os IDs dos anexos removidos para
// que os arquivos sejam apagados do disco.
func (s *Store) PurgeExpired(ctx context.Context, retention time.Duration) ([]uuid.UUID, error) {
	if _, err := s.pool.Exec(ctx, `DELETE FROM envelopes WHERE created_at < now() - make_interval(secs => $1)`, retention.Seconds()); err != nil {
		return nil, err
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM otp_challenges WHERE expires_at < now()`); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `DELETE FROM attachments WHERE expires_at < now() RETURNING id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

func (s *Store) CreateAttachment(ctx context.Context, id, uploader uuid.UUID, size int64, ttl time.Duration) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO attachments (id, uploader_id, size_bytes, expires_at)
		VALUES ($1, $2, $3, now() + make_interval(secs => $4))`, id, uploader, size, ttl.Seconds())
	return err
}

// AttachmentExists informa se o anexo existe e não expirou.
func (s *Store) AttachmentExists(ctx context.Context, id uuid.UUID) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM attachments WHERE id = $1 AND expires_at > now())`, id).Scan(&ok)
	return ok, err
}
