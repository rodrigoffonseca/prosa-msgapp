package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/blob"
)

// handleUploadAttachment recebe um anexo já cifrado pelo cliente (corpo
// binário). A chave de decifração viaja apenas dentro da mensagem E2EE.
func (s *Server) handleUploadAttachment(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > s.cfg.MaxAttachmentBytes {
		writeError(w, http.StatusRequestEntityTooLarge, blob.ErrTooLarge.Error())
		return
	}
	id := uuid.New()
	n, err := s.blobs.Put(id, r.Body, s.cfg.MaxAttachmentBytes)
	if errors.Is(err, blob.ErrTooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "falha ao receber o anexo: "+err.Error())
		return
	}
	if err := s.store.CreateAttachment(r.Context(), id, currentUser(r).ID, n, s.cfg.RetentionPeriod); err != nil {
		_ = s.blobs.Delete(id)
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "size": n})
}

func (s *Server) handleDownloadAttachment(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	exists, err := s.store.AttachmentExists(r.Context(), id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !exists {
		writeError(w, http.StatusNotFound, "anexo não encontrado ou expirado")
		return
	}
	f, err := s.blobs.Open(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "anexo não encontrado ou expirado")
		return
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "private, max-age=86400, immutable")
	_, _ = io.Copy(w, f)
}
