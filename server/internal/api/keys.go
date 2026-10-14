package api

import (
	"errors"
	"net/http"

	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/store"
)

const (
	publicKeyLen = 32
	signatureLen = 64
	maxKeysBatch = 200
)

func validPreKeys(keys []store.PreKey) bool {
	if len(keys) > maxKeysBatch {
		return false
	}
	for _, k := range keys {
		if k.ID < 0 || len(k.PublicKey) != publicKeyLen {
			return false
		}
	}
	return true
}

func (s *Server) handlePutKeys(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RegistrationID int                `json:"registration_id"`
		IdentityKey    []byte             `json:"identity_key"`
		SignedPreKey   store.SignedPreKey `json:"signed_prekey"`
		OneTimePreKeys []store.PreKey     `json:"one_time_prekeys"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	// A assinatura da signed prekey é verificada pelos clientes, que são quem
	// precisa confiar nela; o servidor só valida o formato.
	if req.RegistrationID < 1 || len(req.IdentityKey) != publicKeyLen || len(req.SignedPreKey.PublicKey) != publicKeyLen ||
		len(req.SignedPreKey.Signature) != signatureLen || req.SignedPreKey.ID < 0 || !validPreKeys(req.OneTimePreKeys) {
		writeError(w, http.StatusBadRequest, "chaves em formato inválido")
		return
	}
	err := s.store.SetKeys(r.Context(), currentUser(r).ID, req.RegistrationID, req.IdentityKey, req.SignedPreKey, req.OneTimePreKeys)
	s.keysResult(w, r, err)
}

func (s *Server) handleAddOneTimeKeys(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OneTimePreKeys []store.PreKey `json:"one_time_prekeys"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !validPreKeys(req.OneTimePreKeys) {
		writeError(w, http.StatusBadRequest, "chaves em formato inválido")
		return
	}
	err := s.store.AddOneTimePreKeys(r.Context(), currentUser(r).ID, req.OneTimePreKeys)
	s.keysResult(w, r, err)
}

func (s *Server) keysResult(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrTooManyKeys):
		writeError(w, http.StatusBadRequest, err.Error())
	case err != nil:
		s.internalError(w, r, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleCountKeys(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountOneTimePreKeys(r.Context(), currentUser(r).ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"one_time_prekeys": n})
}

func (s *Server) handleGetBundle(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "userId")
	if !ok {
		return
	}
	// Cada busca consome uma one-time prekey; limitamos para impedir que
	// alguém esgote as chaves de outra pessoa.
	if !s.bundleLimiter.Allow(currentUser(r).ID.String()) {
		writeError(w, http.StatusTooManyRequests, "muitas solicitações de chaves; tente mais tarde")
		return
	}
	b, err := s.store.TakePreKeyBundle(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "usuário sem chaves publicadas")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}
