package api

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/store"
)

const maxGroupName = 64

func normalizeGroupName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	return name, name != "" && utf8.RuneCountInString(name) <= maxGroupName
}

// requireMember carrega o papel do usuário atual no grupo. Não membros
// recebem 404 para não revelar a existência do grupo.
func (s *Server) requireMember(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	gid, ok := pathUUID(w, r, "id")
	if !ok {
		return uuid.Nil, "", false
	}
	role, err := s.store.MemberRole(r.Context(), gid, currentUser(r).ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "grupo não encontrado")
		return uuid.Nil, "", false
	}
	if err != nil {
		s.internalError(w, r, err)
		return uuid.Nil, "", false
	}
	return gid, role, true
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	gid, role, ok := s.requireMember(w, r)
	if !ok {
		return uuid.Nil, false
	}
	if role != store.RoleAdmin {
		writeError(w, http.StatusForbidden, "apenas administradores podem fazer isso")
		return uuid.Nil, false
	}
	return gid, true
}

func (s *Server) writeGroup(w http.ResponseWriter, r *http.Request, status int, gid uuid.UUID) {
	g, err := s.store.GetGroup(r.Context(), gid)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, status, g)
}

func (s *Server) membersError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "um ou mais usuários não existem")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "o grupo excederia o limite de membros")
	default:
		s.internalError(w, r, err)
	}
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string      `json:"name"`
		Members []uuid.UUID `json:"members"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name, ok := normalizeGroupName(req.Name)
	if !ok {
		writeError(w, http.StatusBadRequest, "nome do grupo deve ter de 1 a 64 caracteres")
		return
	}
	me := currentUser(r).ID
	members := slices.DeleteFunc(slices.Clone(req.Members), func(id uuid.UUID) bool { return id == me })
	g, err := s.store.CreateGroup(r.Context(), me, name, members)
	if err != nil {
		s.membersError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListGroupsForUser(r.Context(), currentUser(r).ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	gid, _, ok := s.requireMember(w, r)
	if !ok {
		return
	}
	s.writeGroup(w, r, http.StatusOK, gid)
}

func (s *Server) handleRenameGroup(w http.ResponseWriter, r *http.Request) {
	gid, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name, ok := normalizeGroupName(req.Name)
	if !ok {
		writeError(w, http.StatusBadRequest, "nome do grupo deve ter de 1 a 64 caracteres")
		return
	}
	if err := s.store.RenameGroup(r.Context(), gid, name); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.writeGroup(w, r, http.StatusOK, gid)
}

func (s *Server) handleAddMembers(w http.ResponseWriter, r *http.Request) {
	gid, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		UserIDs []uuid.UUID `json:"user_ids"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.UserIDs) == 0 {
		writeError(w, http.StatusBadRequest, "informe ao menos um usuário")
		return
	}
	if err := s.store.AddGroupMembers(r.Context(), gid, req.UserIDs); err != nil {
		s.membersError(w, r, err)
		return
	}
	s.writeGroup(w, r, http.StatusOK, gid)
}

// handleRemoveMember remove um membro (apenas administradores) ou permite que
// o próprio usuário saia do grupo.
func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	gid, role, ok := s.requireMember(w, r)
	if !ok {
		return
	}
	target, ok := pathUUID(w, r, "userId")
	if !ok {
		return
	}
	if target != currentUser(r).ID && role != store.RoleAdmin {
		writeError(w, http.StatusForbidden, "apenas administradores podem remover membros")
		return
	}
	err := s.store.RemoveGroupMember(r.Context(), gid, target)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "usuário não é membro do grupo")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetRole(w http.ResponseWriter, r *http.Request) {
	gid, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	target, ok := pathUUID(w, r, "userId")
	if !ok {
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Role != store.RoleAdmin && req.Role != store.RoleMember {
		writeError(w, http.StatusBadRequest, "papel deve ser 'admin' ou 'member'")
		return
	}
	err := s.store.SetGroupMemberRole(r.Context(), gid, target, req.Role)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "usuário não é membro do grupo")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.writeGroup(w, r, http.StatusOK, gid)
}

// handleSendGroup recebe uma cópia cifrada da mensagem para cada membro
// (fan-out no cliente). Os destinatários precisam corresponder exatamente aos
// membros atuais, para que ninguém fique de fora nem receba sem ser membro.
func (s *Server) handleSendGroup(w http.ResponseWriter, r *http.Request) {
	gid, _, ok := s.requireMember(w, r)
	if !ok {
		return
	}
	msgs, ok := s.readOutgoing(w, r)
	if !ok {
		return
	}
	me := currentUser(r).ID
	members, err := s.store.GroupMemberIDs(r.Context(), gid)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	expected := map[uuid.UUID]bool{}
	for _, id := range members {
		if id != me {
			expected[id] = true
		}
	}
	match := len(msgs) == len(expected)
	for _, m := range msgs {
		match = match && expected[m.To]
	}
	if !match {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":   "lista de destinatários difere dos membros do grupo",
			"members": members,
		})
		return
	}
	s.deliver(w, r, me, &gid, msgs)
}
