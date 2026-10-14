// Package sms envia os códigos de verificação por SMS.
package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type Sender interface {
	SendCode(ctx context.Context, e164, code string) error
}

// Console apenas registra o código no log. Uso exclusivo em desenvolvimento.
type Console struct{ Log *slog.Logger }

func (c Console) SendCode(_ context.Context, e164, code string) error {
	c.Log.Warn("SMS (console, apenas desenvolvimento)", "to", e164, "code", code)
	return nil
}

// Webhook envia o código para um serviço HTTP próprio, permitindo integrar
// qualquer provedor de SMS (de preferência nacional) sem acoplar o servidor
// a um fornecedor específico.
//
// Requisição: POST {URL} com JSON {"to": "+55...", "message": "..."} e
// cabeçalho "Authorization: Bearer {Key}".
type Webhook struct {
	URL    string
	Key    string
	Client *http.Client
}

func (w Webhook) SendCode(ctx context.Context, e164, code string) error {
	body, _ := json.Marshal(map[string]string{
		"to":      e164,
		"message": fmt.Sprintf("Seu código Prosa é %s. Não compartilhe com ninguém.", code),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.Key != "" {
		req.Header.Set("Authorization", "Bearer "+w.Key)
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("provedor de SMS respondeu %s", resp.Status)
	}
	return nil
}
