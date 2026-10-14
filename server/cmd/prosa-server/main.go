// Comando prosa-server: servidor de mensagens do Prosa.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/api"
	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/blob"
	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/config"
	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/sms"
	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("encerrando", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.DevExposeOTP {
		log.Warn("PROSA_DEV_EXPOSE_OTP ativo: códigos de verificação são devolvidos pela API. Nunca use em produção.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}

	blobs, err := blob.NewFS(cfg.BlobDir)
	if err != nil {
		return err
	}

	var sender sms.Sender
	switch cfg.SMSProvider {
	case "console":
		sender = sms.Console{Log: log}
	case "webhook":
		sender = sms.Webhook{URL: cfg.SMSWebhookURL, Key: cfg.SMSWebhookKey}
	default:
		return errors.New("PROSA_SMS_PROVIDER desconhecido: " + cfg.SMSProvider)
	}

	srv := api.New(cfg, st, blobs, sender, log)
	go srv.RunJanitor(ctx, time.Hour)

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("servidor Prosa ouvindo", "addr", cfg.ListenAddr, "env", cfg.Env)
		errc <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}
