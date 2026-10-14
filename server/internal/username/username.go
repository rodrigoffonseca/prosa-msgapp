// Package username valida e normaliza nomes de usuário.
package username

import (
	"errors"
	"regexp"
	"strings"
)

var (
	ErrInvalid  = errors.New("nome de usuário deve ter de 3 a 32 caracteres, começar com letra e conter apenas letras minúsculas, números, '_' ou '.'")
	ErrReserved = errors.New("nome de usuário reservado")

	pattern = regexp.MustCompile(`^[a-z][a-z0-9_.]{2,31}$`)

	reserved = map[string]bool{
		"admin": true, "administrador": true, "root": true, "prosa": true,
		"suporte": true, "support": true, "sistema": true, "system": true,
		"oficial": true, "seguranca": true, "security": true, "moderador": true,
	}
)

// Normalize devolve o nome em minúsculas, validado.
func Normalize(raw string) (string, error) {
	u := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(raw), "@"))
	if !pattern.MatchString(u) || strings.Contains(u, "..") || strings.HasSuffix(u, ".") {
		return "", ErrInvalid
	}
	if reserved[u] {
		return "", ErrReserved
	}
	return u, nil
}
