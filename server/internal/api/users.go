package api

import (
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/phone"
	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/store"
	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/username"
)

const maxDisplayName = 64

func (s *Server) handleGetMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, currentUser(r))
}

func (s *Server) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    *string `json:"username"`
		DisplayName *string `json:"display_name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Username != nil {
		u, err := username.Normalize(*req.Username)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Username = &u
	}
	if req.DisplayName != nil {
		d := strings.TrimSpace(*req.DisplayName)
		if d == "" || utf8.RuneCountInString(d) > maxDisplayName {
			writeError(w, http.StatusBadRequest, "nome de exibição deve ter de 1 a 64 caracteres")
			return
		}
		req.DisplayName = &d
	}
	u, err := s.store.UpdateProfile(r.Context(), currentUser(r).ID, req.Username, req.DisplayName)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "nome de usuário já está em uso")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleDeleteMe(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	groups, err := s.store.ListGroupsForUser(r.Context(), me.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	// Sai dos grupos antes, para que eles recebam um novo administrador.
	for _, g := range groups {
		if err := s.store.RemoveGroupMember(r.Context(), g.ID, me.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internalError(w, r, err)
			return
		}
	}
	if err := s.store.DeleteUser(r.Context(), me.ID); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.hub.Disconnect(me.ID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) writeUser(w http.ResponseWriter, r *http.Request, u *store.User, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "usuário não encontrado")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	u, err := s.store.GetUser(r.Context(), id)
	s.writeUser(w, r, u, err)
}

func (s *Server) handleGetUserByUsername(w http.ResponseWriter, r *http.Request) {
	name, err := username.Normalize(r.PathValue("username"))
	if err != nil {
		writeError(w, http.StatusNotFound, "usuário não encontrado")
		return
	}
	u, err := s.store.GetUserByUsername(r.Context(), name)
	s.writeUser(w, r, u, err)
}

// handleLookupPhone encontra um contato pelo telefone. É limitado por usuário
// para dificultar a enumeração da base.
func (s *Server) handleLookupPhone(w http.ResponseWriter, r *http.Request) {
	if !s.lookupLimiter.Allow(currentUser(r).ID.String()) {
		writeError(w, http.StatusTooManyRequests, "limite de buscas por telefone atingido; tente mais tarde")
		return
	}
	var req struct {
		Phone string `json:"phone"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	e164, err := phone.Normalize(req.Phone)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.store.GetUserByPhoneHash(r.Context(), phone.Hash(s.cfg.PhonePepper, e164))
	s.writeUser(w, r, u, err)
}
