// Package store implementa a persistência em PostgreSQL.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var (
	ErrNotFound = errors.New("não encontrado")
	ErrConflict = errors.New("conflito")
)

type Store struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, url string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("conectando ao banco: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// Migrate aplica, em ordem, as migrações ainda não aplicadas.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			// Serializa migrações concorrentes de várias instâncias.
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7072)`); err != nil {
				return err
			}
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)`, name).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return nil
			}
			sql, err := migrationsFS.ReadFile(name)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("migração %s: %w", name, err)
			}
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(name) VALUES ($1)`, name)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
