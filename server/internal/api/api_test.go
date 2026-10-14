package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/blob"
	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/config"
	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/sms"
	"github.com/rodrigoffonseca/prosa-msgapp/server/internal/store"
)

// Os testes de integração precisam de um PostgreSQL descartável:
//
//	PROSA_TEST_DATABASE_URL=postgres://prosa@localhost:5432/prosa_test go test ./...
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	url := os.Getenv("PROSA_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PROSA_TEST_DATABASE_URL não definido")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	blobs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Env:                "development",
		PhonePepper:        []byte(fmt.Sprintf("test-pepper-%d", time.Now().UnixNano())),
		DevExposeOTP:       true,
		MaxAttachmentBytes: 1 << 20,
		RetentionPeriod:    time.Hour,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(cfg, st, blobs, sms.Console{Log: log}, log)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

type client struct {
	t     *testing.T
	base  string
	token string
	id    string
}

func (c *client) do(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	var rd io.Reader
	if b, ok := body.([]byte); ok {
		rd = bytes.NewReader(b)
	} else if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{"_raw": string(raw)}
	}
	return resp.StatusCode, out
}

func (c *client) must(want int, method, path string, body any) map[string]any {
	c.t.Helper()
	got, out := c.do(method, path, body)
	if got != want {
		c.t.Fatalf("%s %s: status %d, quero %d: %v", method, path, got, want, out)
	}
	return out
}

var phoneSeq = time.Now().UnixNano() % 100_000_000

func register(t *testing.T, base string) *client {
	t.Helper()
	phoneSeq++
	ph := fmt.Sprintf("+55119%08d", phoneSeq%100_000_000)
	c := &client{t: t, base: base}
	out := c.must(202, "POST", "/v1/auth/request-code", map[string]string{"phone": ph})
	code := out["dev_code"].(string)
	c.must(401, "POST", "/v1/auth/verify", map[string]string{"phone": ph, "code": "x" + code})
	out = c.must(200, "POST", "/v1/auth/verify", map[string]string{"phone": ph, "code": code})
	c.token = out["token"].(string)
	c.id = out["user"].(map[string]any)["id"].(string)
	// Código já usado não vale de novo.
	(&client{t: t, base: base}).must(401, "POST", "/v1/auth/verify", map[string]string{"phone": ph, "code": code})
	return c
}

func key(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

// withKeys publica chaves (fictícias) com registration_id 7.
func withKeys(cs ...*client) {
	for _, c := range cs {
		c.must(204, "PUT", "/v1/keys", map[string]any{
			"registration_id": 7,
			"identity_key":    key(1, 32),
			"signed_prekey":   map[string]any{"id": 1, "public_key": key(2, 32), "signature": key(3, 64)},
		})
	}
}

func TestAccountsAndKeys(t *testing.T) {
	ts := newTestServer(t)
	alice, bob := register(t, ts.URL), register(t, ts.URL)

	(&client{t: t, base: ts.URL}).must(401, "GET", "/v1/me", nil)

	uname := fmt.Sprintf("alice%d", phoneSeq)
	alice.must(200, "PATCH", "/v1/me", map[string]any{"username": strings.ToUpper(uname), "display_name": "Alice"})
	bob.must(409, "PATCH", "/v1/me", map[string]any{"username": uname})
	bob.must(400, "PATCH", "/v1/me", map[string]any{"username": "admin"})
	got := bob.must(200, "GET", "/v1/users/by-username/@"+uname, nil)
	if got["id"] != alice.id {
		t.Fatalf("busca por username devolveu %v", got)
	}

	alice.must(204, "PUT", "/v1/keys", map[string]any{
		"registration_id":  7,
		"identity_key":     key(1, 32),
		"signed_prekey":    map[string]any{"id": 1, "public_key": key(2, 32), "signature": key(3, 64)},
		"one_time_prekeys": []map[string]any{{"id": 1, "public_key": key(4, 32)}, {"id": 2, "public_key": key(5, 32)}},
	})
	alice.must(400, "PUT", "/v1/keys", map[string]any{
		"registration_id": 7,
		"identity_key":    key(1, 31),
		"signed_prekey":   map[string]any{"id": 1, "public_key": key(2, 32), "signature": key(3, 64)},
	})
	if n := alice.must(200, "GET", "/v1/keys/count", nil)["one_time_prekeys"]; n != float64(2) {
		t.Fatalf("contagem de chaves = %v", n)
	}
	for i, want := range []any{float64(1), float64(2), nil} {
		b := bob.must(200, "GET", "/v1/keys/"+alice.id, nil)
		var gotID any
		if otk, ok := b["one_time_prekey"].(map[string]any); ok {
			gotID = otk["id"]
		}
		if gotID != want {
			t.Fatalf("busca %d: one-time prekey %v, quero %v", i, gotID, want)
		}
	}
	bob.must(404, "GET", "/v1/keys/"+bob.id, nil)
}

func TestDirectMessagesAndWebSocket(t *testing.T) {
	ts := newTestServer(t)
	alice, bob := register(t, ts.URL), register(t, ts.URL)
	withKeys(alice, bob)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/ws?token=" + bob.token
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	var msg map[string]any
	if err := wsjson.Read(ctx, conn, &msg); err != nil || msg["type"] != "ready" {
		t.Fatalf("esperava ready: %v %v", msg, err)
	}

	out := alice.must(201, "POST", "/v1/messages", map[string]any{
		"messages": []map[string]any{{"to": bob.id, "registration_id": 7, "ciphertext": []byte("cifrado")}},
	})
	sentID := out["messages"].([]any)[0].(map[string]any)["id"]

	if err := wsjson.Read(ctx, conn, &msg); err != nil {
		t.Fatal(err)
	}
	env := msg["envelope"].(map[string]any)
	if msg["type"] != "envelope" || env["id"] != sentID || env["sender_id"] != alice.id {
		t.Fatalf("envelope inesperado: %v", msg)
	}

	pending := bob.must(200, "GET", "/v1/messages", nil)["envelopes"].([]any)
	if len(pending) != 1 {
		t.Fatalf("pendentes = %d", len(pending))
	}
	// Alice não consegue confirmar (apagar) mensagens do Bob.
	alice.must(204, "POST", "/v1/messages/ack", map[string]any{"ids": []any{sentID}})
	if n := len(bob.must(200, "GET", "/v1/messages", nil)["envelopes"].([]any)); n != 1 {
		t.Fatal("ack de outro usuário apagou a mensagem")
	}
	if err := wsjson.Write(ctx, conn, map[string]any{"type": "ack", "ids": []any{sentID}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(bob.must(200, "GET", "/v1/messages", nil)["envelopes"].([]any)) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("ack via websocket não apagou o envelope")
		}
		time.Sleep(50 * time.Millisecond)
	}

	alice.must(404, "POST", "/v1/messages", map[string]any{
		"messages": []map[string]any{{"to": "00000000-0000-0000-0000-000000000000", "registration_id": 7, "ciphertext": []byte("x")}},
	})
	alice.must(400, "POST", "/v1/messages", map[string]any{
		"messages": []map[string]any{{"to": bob.id, "registration_id": 7, "ciphertext": make([]byte, maxCiphertextSize+1)}},
	})
	// Instalação desatualizada: o remetente precisa refazer a sessão.
	out = alice.must(410, "POST", "/v1/messages", map[string]any{
		"messages": []map[string]any{{"to": bob.id, "registration_id": 8, "ciphertext": []byte("x")}},
	})
	if stale := out["stale"].([]any); len(stale) != 1 || stale[0] != bob.id {
		t.Fatalf("stale = %v", out["stale"])
	}
}

func TestGroups(t *testing.T) {
	ts := newTestServer(t)
	alice, bob, carol, eve := register(t, ts.URL), register(t, ts.URL), register(t, ts.URL), register(t, ts.URL)
	withKeys(alice, bob, carol, eve)

	g := alice.must(201, "POST", "/v1/groups", map[string]any{"name": "Família", "members": []string{bob.id, alice.id}})
	gid := g["id"].(string)
	if n := len(g["members"].([]any)); n != 2 {
		t.Fatalf("membros = %d", n)
	}

	eve.must(404, "GET", "/v1/groups/"+gid, nil)
	bob.must(403, "POST", "/v1/groups/"+gid+"/members", map[string]any{"user_ids": []string{eve.id}})
	alice.must(200, "POST", "/v1/groups/"+gid+"/members", map[string]any{"user_ids": []string{carol.id}})

	send := func(c *client, to ...*client) (int, map[string]any) {
		var msgs []map[string]any
		for _, r := range to {
			msgs = append(msgs, map[string]any{"to": r.id, "registration_id": 7, "ciphertext": []byte("oi")})
		}
		return c.do("POST", "/v1/groups/"+gid+"/messages", map[string]any{"messages": msgs})
	}
	if st, _ := send(alice, bob); st != 409 {
		t.Fatalf("faltando destinatário: status %d", st)
	}
	if st, _ := send(alice, bob, carol, eve); st != 409 {
		t.Fatalf("destinatário extra: status %d", st)
	}
	if st, out := send(alice, bob, carol); st != 201 {
		t.Fatalf("envio ao grupo: %d %v", st, out)
	}
	if st, _ := send(eve, alice, bob, carol); st != 404 {
		t.Fatalf("não membro enviando: %d", st)
	}
	env := carol.must(200, "GET", "/v1/messages", nil)["envelopes"].([]any)[0].(map[string]any)
	if env["group_id"] != gid {
		t.Fatalf("envelope sem group_id: %v", env)
	}

	bob.must(403, "DELETE", "/v1/groups/"+gid+"/members/"+carol.id, nil)
	bob.must(204, "DELETE", "/v1/groups/"+gid+"/members/"+bob.id, nil) // sair
	alice.must(204, "DELETE", "/v1/groups/"+gid+"/members/"+alice.id, nil)
	// Carol, a última, vira administradora automaticamente.
	g = carol.must(200, "PATCH", "/v1/groups/"+gid, map[string]any{"name": "Nova"})
	if g["name"] != "Nova" || g["members"].([]any)[0].(map[string]any)["role"] != "admin" {
		t.Fatalf("grupo inesperado: %v", g)
	}
}

func TestAttachments(t *testing.T) {
	ts := newTestServer(t)
	alice, bob := register(t, ts.URL), register(t, ts.URL)

	data := bytes.Repeat([]byte{0xAB}, 4096)
	out := alice.must(201, "POST", "/v1/attachments", data)
	id := out["id"].(string)

	req, _ := http.NewRequest("GET", ts.URL+"/v1/attachments/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+bob.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(got, data) {
		t.Fatalf("download: status %d, %d bytes", resp.StatusCode, len(got))
	}

	alice.must(413, "POST", "/v1/attachments", make([]byte, (1<<20)+1))
	bob.must(404, "GET", "/v1/attachments/00000000-0000-0000-0000-000000000000", nil)
}

func TestReRegistrationRevokesOldDevice(t *testing.T) {
	ts := newTestServer(t)
	anon := &client{t: t, base: ts.URL}
	ph := fmt.Sprintf("+55219%08d", time.Now().UnixNano()%100_000_000)
	requestCode := func() string {
		return anon.must(202, "POST", "/v1/auth/request-code", map[string]string{"phone": ph})["dev_code"].(string)
	}
	verify := func(code string) *client {
		out := anon.must(200, "POST", "/v1/auth/verify", map[string]string{"phone": ph, "code": code})
		return &client{t: t, base: ts.URL, token: out["token"].(string), id: out["user"].(map[string]any)["id"].(string)}
	}

	old := verify(requestCode())
	old.must(204, "PUT", "/v1/keys", map[string]any{
		"registration_id": 7,
		"identity_key":    key(1, 32),
		"signed_prekey":   map[string]any{"id": 1, "public_key": key(2, 32), "signature": key(3, 64)},
	})
	friend := register(t, ts.URL)
	withKeys(friend)
	friend.must(201, "POST", "/v1/messages", map[string]any{
		"messages": []map[string]any{{"to": old.id, "registration_id": 7, "ciphertext": []byte("x")}},
	})

	code := requestCode()
	// Novo pedido logo em seguida é recusado enquanto o desafio anterior vale.
	anon.must(429, "POST", "/v1/auth/request-code", map[string]string{"phone": ph})

	fresh := verify(code)
	if fresh.id != old.id {
		t.Fatal("reinstalação deveria manter a mesma conta")
	}
	old.must(401, "GET", "/v1/me", nil)
	friend.must(404, "GET", "/v1/keys/"+fresh.id, nil)
	if n := len(fresh.must(200, "GET", "/v1/messages", nil)["envelopes"].([]any)); n != 0 {
		t.Fatalf("mensagens do aparelho antigo deveriam ser descartadas, restaram %d", n)
	}
}
