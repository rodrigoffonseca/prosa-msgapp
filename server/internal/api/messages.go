package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/google/uuid"

	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/store"
)

const maxRecipientsPerRequest = store.MaxGroupMembers

type outgoing struct {
	To uuid.UUID `json:"to"`
	// RegistrationID é o da instalação para a qual a mensagem foi cifrada.
	RegistrationID int    `json:"registration_id"`
	Ciphertext     []byte `json:"ciphertext"`
}

type sentResult struct {
	ID              uuid.UUID `json:"id"`
	To              uuid.UUID `json:"to"`
	ServerTimestamp time.Time `json:"server_timestamp"`
}

func (s *Server) readOutgoing(w http.ResponseWriter, r *http.Request) ([]outgoing, bool) {
	var req struct {
		Messages []outgoing `json:"messages"`
	}
	if !readJSON(w, r, &req) {
		return nil, false
	}
	if len(req.Messages) == 0 || len(req.Messages) > maxRecipientsPerRequest {
		writeError(w, http.StatusBadRequest, "quantidade de mensagens inválida")
		return nil, false
	}
	seen := map[uuid.UUID]bool{}
	for _, m := range req.Messages {
		if len(m.Ciphertext) == 0 || len(m.Ciphertext) > maxCiphertextSize {
			writeError(w, http.StatusBadRequest, "mensagem vazia ou grande demais")
			return nil, false
		}
		if seen[m.To] {
			writeError(w, http.StatusBadRequest, "destinatário repetido")
			return nil, false
		}
		seen[m.To] = true
	}
	return req.Messages, true
}

func (s *Server) deliver(w http.ResponseWriter, r *http.Request, sender uuid.UUID, groupID *uuid.UUID, msgs []outgoing) {
	// Recusa mensagens cifradas para uma instalação que não existe mais
	// (o destinatário reinstalou o app). O remetente deve buscar as chaves
	// novas, refazer a sessão e reenviar.
	ids := make([]uuid.UUID, len(msgs))
	for i, m := range msgs {
		ids[i] = m.To
	}
	current, err := s.store.RegistrationIDs(r.Context(), ids)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	stale := []uuid.UUID{}
	for _, m := range msgs {
		if reg, ok := current[m.To]; !ok || reg != m.RegistrationID {
			stale = append(stale, m.To)
		}
	}
	if len(stale) > 0 {
		writeJSON(w, http.StatusGone, map[string]any{
			"error": "sessão desatualizada com um ou mais destinatários",
			"stale": stale,
		})
		return
	}

	envs := make([]*store.Envelope, len(msgs))
	for i, m := range msgs {
		envs[i] = &store.Envelope{RecipientID: m.To, SenderID: sender, GroupID: groupID, Ciphertext: m.Ciphertext}
	}
	if err := s.store.InsertEnvelopes(r.Context(), envs); err != nil {
		s.internalError(w, r, err)
		return
	}
	res := make([]sentResult, len(envs))
	for i, e := range envs {
		s.hub.Notify(e.RecipientID, e)
		res[i] = sentResult{ID: e.ID, To: e.RecipientID, ServerTimestamp: e.CreatedAt}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"messages": res})
}

func (s *Server) handleSendDirect(w http.ResponseWriter, r *http.Request) {
	msgs, ok := s.readOutgoing(w, r)
	if !ok {
		return
	}
	for _, m := range msgs {
		if _, err := s.store.GetUser(r.Context(), m.To); errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "destinatário não encontrado: "+m.To.String())
			return
		} else if err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	s.deliver(w, r, currentUser(r).ID, nil, msgs)
}

func (s *Server) handleListPending(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "limit deve estar entre 1 e 500")
			return
		}
		limit = n
	}
	envs, err := s.store.PendingEnvelopes(r.Context(), currentUser(r).ID, limit)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"envelopes": envs})
}

func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []uuid.UUID `json:"ids"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.IDs) > 500 {
		writeError(w, http.StatusBadRequest, "máximo de 500 confirmações por requisição")
		return
	}
	if err := s.store.AckEnvelopes(r.Context(), currentUser(r).ID, req.IDs); err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleWebSocket abre o canal de entrega em tempo real.
//
// Protocolo: ao conectar, o servidor envia {"type":"ready"}. A partir daí,
// toda mensagem nova chega como {"type":"envelope","envelope":{...}}. O
// cliente deve, após receber "ready", buscar o que estiver pendente via
// GET /v1/messages (pode haver duplicatas; deduplique pelo id) e confirmar o
// recebimento com {"type":"ack","ids":[...]} ou POST /v1/messages/ack.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	// A autenticação é por token (não por cookie), então não há risco de
	// CSRF entre origens e qualquer origem pode conectar.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(64 << 10)

	sub := s.hub.Subscribe(me.ID)
	defer s.hub.Unsubscribe(me.ID, sub)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	go func() {
		defer cancel()
		for {
			var msg struct {
				Type string      `json:"type"`
				IDs  []uuid.UUID `json:"ids"`
			}
			if err := wsjson.Read(ctx, conn, &msg); err != nil {
				return
			}
			if msg.Type == "ack" && len(msg.IDs) > 0 && len(msg.IDs) <= 500 {
				if err := s.store.AckEnvelopes(ctx, me.ID, msg.IDs); err != nil {
					s.log.Error("ack via websocket", "err", err)
				}
			}
		}
	}()

	if err := wsjson.Write(ctx, conn, map[string]string{"type": "ready"}); err != nil {
		return
	}
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sub.closed:
			conn.Close(websocket.StatusPolicyViolation, "reconecte")
			return
		case env := <-sub.ch:
			if err := wsjson.Write(ctx, conn, map[string]any{"type": "envelope", "envelope": env}); err != nil {
				return
			}
		case <-ping.C:
			pctx, pcancel := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Ping(pctx)
			pcancel()
			if err != nil {
				return
			}
		}
	}
}
