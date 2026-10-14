// Package api implementa a API HTTP e WebSocket do servidor Prosa.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/blob"
	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/config"
	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/sms"
	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/store"
)

const (
	maxJSONBody       = 1 << 20
	maxCiphertextSize = 64 << 10
)

type Server struct {
	cfg   *config.Config
	store *store.Store
	blobs *blob.FS
	sms   sms.Sender
	log   *slog.Logger
	hub   *Hub

	// Limites por IP são generosos porque operadoras móveis brasileiras usam
	// CGNAT intensamente (muitos usuários compartilham o mesmo IP).
	otpLimiter    *RateLimiter // por IP
	phoneLimiter  *RateLimiter // por telefone
	verifyLimiter *RateLimiter // por IP
	lookupLimiter *RateLimiter // por usuário
	bundleLimiter *RateLimiter // por usuário
}

func New(cfg *config.Config, st *store.Store, blobs *blob.FS, sender sms.Sender, log *slog.Logger) *Server {
	return &Server{
		cfg:           cfg,
		store:         st,
		blobs:         blobs,
		sms:           sender,
		log:           log,
		hub:           NewHub(),
		otpLimiter:    NewRateLimiter(60, time.Hour),
		phoneLimiter:  NewRateLimiter(5, time.Hour),
		verifyLimiter: NewRateLimiter(300, time.Hour),
		lookupLimiter: NewRateLimiter(120, time.Hour),
		bundleLimiter: NewRateLimiter(600, time.Hour),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /v1/auth/request-code", s.handleRequestCode)
	mux.HandleFunc("POST /v1/auth/verify", s.handleVerify)
	mux.Handle("POST /v1/auth/logout", s.authed(s.handleLogout))

	mux.Handle("GET /v1/me", s.authed(s.handleGetMe))
	mux.Handle("PATCH /v1/me", s.authed(s.handleUpdateMe))
	mux.Handle("DELETE /v1/me", s.authed(s.handleDeleteMe))
	mux.Handle("GET /v1/users/{id}", s.authed(s.handleGetUser))
	mux.Handle("GET /v1/users/by-username/{username}", s.authed(s.handleGetUserByUsername))
	mux.Handle("POST /v1/users/lookup-phone", s.authed(s.handleLookupPhone))

	mux.Handle("PUT /v1/keys", s.authed(s.handlePutKeys))
	mux.Handle("POST /v1/keys/one-time", s.authed(s.handleAddOneTimeKeys))
	mux.Handle("GET /v1/keys/count", s.authed(s.handleCountKeys))
	mux.Handle("GET /v1/keys/{userId}", s.authed(s.handleGetBundle))

	mux.Handle("POST /v1/messages", s.authed(s.handleSendDirect))
	mux.Handle("GET /v1/messages", s.authed(s.handleListPending))
	mux.Handle("POST /v1/messages/ack", s.authed(s.handleAck))
	mux.Handle("GET /v1/ws", s.authed(s.handleWebSocket))

	mux.Handle("POST /v1/groups", s.authed(s.handleCreateGroup))
	mux.Handle("GET /v1/groups", s.authed(s.handleListGroups))
	mux.Handle("GET /v1/groups/{id}", s.authed(s.handleGetGroup))
	mux.Handle("PATCH /v1/groups/{id}", s.authed(s.handleRenameGroup))
	mux.Handle("POST /v1/groups/{id}/members", s.authed(s.handleAddMembers))
	mux.Handle("DELETE /v1/groups/{id}/members/{userId}", s.authed(s.handleRemoveMember))
	mux.Handle("PUT /v1/groups/{id}/members/{userId}/role", s.authed(s.handleSetRole))
	mux.Handle("POST /v1/groups/{id}/messages", s.authed(s.handleSendGroup))

	mux.Handle("POST /v1/attachments", s.authed(s.handleUploadAttachment))
	mux.Handle("GET /v1/attachments/{id}", s.authed(s.handleDownloadAttachment))

	return s.logRequests(mux)
}

// RunJanitor apaga periodicamente dados expirados.
func (s *Server) RunJanitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		ids, err := s.store.PurgeExpired(ctx, s.cfg.RetentionPeriod)
		if err != nil {
			s.log.Error("limpeza de dados expirados", "err", err)
		}
		for _, id := range ids {
			if err := s.blobs.Delete(id); err != nil {
				s.log.Error("apagando anexo expirado", "err", err)
			}
		}
		s.otpLimiter.Cleanup()
		s.verifyLimiter.Cleanup()
		s.phoneLimiter.Cleanup()
		s.lookupLimiter.Cleanup()
		s.bundleLimiter.Cleanup()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---- autenticação ----

type ctxKey struct{}

func currentUser(r *http.Request) *store.User {
	return r.Context().Value(ctxKey{}).(*store.User)
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	// Clientes WebSocket de navegador não conseguem enviar cabeçalhos.
	if r.URL.Path == "/v1/ws" {
		return r.URL.Query().Get("token")
	}
	return ""
}

func (s *Server) authed(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			writeError(w, http.StatusUnauthorized, "autenticação necessária")
			return
		}
		u, err := s.store.UserBySession(r.Context(), hashToken(tok))
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "sessão inválida")
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	})
}

// ---- utilitários ----

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (s *Server) logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rec, r)
		// Não registramos IP, query string nem cabeçalhos: minimização de dados.
		s.log.Info("http", "method", r.Method, "route", r.Pattern, "status", rec.status, "dur", time.Since(start).Round(time.Millisecond))
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("erro interno", "route", r.Pattern, "err", err)
	writeError(w, http.StatusInternalServerError, "erro interno")
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido: "+err.Error())
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "JSON inválido: conteúdo extra após o objeto")
		return false
	}
	return true
}

func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		writeError(w, http.StatusBadRequest, "identificador inválido: "+name)
		return uuid.Nil, false
	}
	return id, true
}
