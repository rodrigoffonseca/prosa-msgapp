package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	RoleAdmin  = "admin"
	RoleMember = "member"

	MaxGroupMembers = 256
)

type GroupMember struct {
	UserID   uuid.UUID `json:"user_id"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

type Group struct {
	ID        uuid.UUID     `json:"id"`
	Name      string        `json:"name"`
	CreatedBy *uuid.UUID    `json:"created_by"`
	CreatedAt time.Time     `json:"created_at"`
	Members   []GroupMember `json:"members"`
}

// CreateGroup cria o grupo com o criador como administrador.
func (s *Store) CreateGroup(ctx context.Context, creator uuid.UUID, name string, members []uuid.UUID) (*Group, error) {
	id := uuid.New()
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO groups (id, name, created_by) VALUES ($1, $2, $3)`, id, name, creator); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'admin')`, id, creator); err != nil {
			return err
		}
		return addMembers(ctx, tx, id, members)
	})
	if err != nil {
		return nil, err
	}
	return s.GetGroup(ctx, id)
}

func addMembers(ctx context.Context, tx pgx.Tx, groupID uuid.UUID, members []uuid.UUID) error {
	if len(members) > 0 {
		var n int
		err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = ANY($1)`, members).Scan(&n)
		if err != nil {
			return err
		}
		if n != len(uniq(members)) {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO group_members (group_id, user_id, role)
			SELECT $1, unnest($2::uuid[]), 'member'
			ON CONFLICT DO NOTHING`, groupID, members)
		if err != nil {
			return err
		}
	}
	var total int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM group_members WHERE group_id = $1`, groupID).Scan(&total); err != nil {
		return err
	}
	if total > MaxGroupMembers {
		return ErrConflict
	}
	return nil
}

func uniq(ids []uuid.UUID) map[uuid.UUID]bool {
	m := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func (s *Store) GetGroup(ctx context.Context, id uuid.UUID) (*Group, error) {
	g := &Group{ID: id}
	err := s.pool.QueryRow(ctx, `SELECT name, created_by, created_at FROM groups WHERE id = $1`, id).
		Scan(&g.Name, &g.CreatedBy, &g.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT user_id, role, joined_at FROM group_members
		 WHERE group_id = $1 ORDER BY joined_at, user_id`, id)
	if err != nil {
		return nil, err
	}
	g.Members, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (GroupMember, error) {
		var m GroupMember
		err := r.Scan(&m.UserID, &m.Role, &m.JoinedAt)
		return m, err
	})
	return g, err
}

func (s *Store) ListGroupsForUser(ctx context.Context, userID uuid.UUID) ([]*Group, error) {
	rows, err := s.pool.Query(ctx, `SELECT group_id FROM group_members WHERE user_id = $1 ORDER BY joined_at`, userID)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	groups := make([]*Group, 0, len(ids))
	for _, id := range ids {
		g, err := s.GetGroup(ctx, id)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, nil
}

// MemberRole devolve o papel do usuário no grupo, ou ErrNotFound se ele não
// for membro.
func (s *Store) MemberRole(ctx context.Context, groupID, userID uuid.UUID) (string, error) {
	var role string
	err := s.pool.QueryRow(ctx, `SELECT role FROM group_members WHERE group_id = $1 AND user_id = $2`, groupID, userID).Scan(&role)
	return role, notFound(err)
}

func (s *Store) AddGroupMembers(ctx context.Context, groupID uuid.UUID, members []uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM groups WHERE id = $1 FOR UPDATE`, groupID); err != nil {
			return err
		}
		return addMembers(ctx, tx, groupID, members)
	})
}

// RemoveGroupMember remove o membro. Se o grupo ficar sem administradores, o
// membro mais antigo é promovido; se ficar vazio, é apagado.
func (s *Store) RemoveGroupMember(ctx context.Context, groupID, userID uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM groups WHERE id = $1 FOR UPDATE`, groupID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, groupID, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		var members, admins int
		err = tx.QueryRow(ctx, `
			SELECT count(*), count(*) FILTER (WHERE role = 'admin')
			  FROM group_members WHERE group_id = $1`, groupID).Scan(&members, &admins)
		if err != nil {
			return err
		}
		switch {
		case members == 0:
			_, err = tx.Exec(ctx, `DELETE FROM groups WHERE id = $1`, groupID)
		case admins == 0:
			_, err = tx.Exec(ctx, `
				UPDATE group_members SET role = 'admin'
				 WHERE (group_id, user_id) = (
				       SELECT group_id, user_id FROM group_members
				        WHERE group_id = $1 ORDER BY joined_at, user_id LIMIT 1)`, groupID)
		}
		return err
	})
}

func (s *Store) SetGroupMemberRole(ctx context.Context, groupID, userID uuid.UUID, role string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE group_members SET role = $3 WHERE group_id = $1 AND user_id = $2`, groupID, userID, role)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) RenameGroup(ctx context.Context, groupID uuid.UUID, name string) error {
	_, err := s.pool.Exec(ctx, `UPDATE groups SET name = $2 WHERE id = $1`, groupID, name)
	return err
}

func (s *Store) GroupMemberIDs(ctx context.Context, groupID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `SELECT user_id FROM group_members WHERE group_id = $1`, groupID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}
