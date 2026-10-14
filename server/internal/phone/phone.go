// Package phone normaliza números de telefone para o formato E.164 e
// calcula o identificador opaco (HMAC) usado para armazená-los.
package phone

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"
)

var ErrInvalid = errors.New("número de telefone inválido")

// Normalize converte a entrada para E.164 (ex.: "+5511987654321").
// Números sem código de país com 10 ou 11 dígitos são tratados como
// brasileiros (DDD + número). Números brasileiros são validados quanto ao
// DDD e ao formato de celular/fixo.
func Normalize(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	hasPlus := strings.HasPrefix(raw, "+")

	var digits strings.Builder
	for _, r := range raw {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case r == '+' || r == ' ' || r == '-' || r == '(' || r == ')' || r == '.':
		default:
			return "", ErrInvalid
		}
	}
	d := digits.String()

	if !hasPlus {
		// Prefixo de discagem internacional usado no Brasil ("00").
		if strings.HasPrefix(d, "00") {
			d = d[2:]
		} else if len(d) == 10 || len(d) == 11 {
			d = "55" + d
		}
	}

	if len(d) < 8 || len(d) > 15 || d[0] == '0' {
		return "", ErrInvalid
	}
	if strings.HasPrefix(d, "55") && !validBrazilian(d[2:]) {
		return "", ErrInvalid
	}
	return "+" + d, nil
}

// validBrazilian valida DDD + número nacional (sem o "55").
func validBrazilian(n string) bool {
	if len(n) != 10 && len(n) != 11 {
		return false
	}
	// DDDs não começam com 0 nem terminam em 0.
	if n[0] == '0' || n[1] == '0' {
		return false
	}
	local := n[2:]
	if len(local) == 9 {
		// Celulares têm 9 dígitos e começam com 9.
		return local[0] == '9'
	}
	// Fixos têm 8 dígitos e começam com 2 a 5.
	return local[0] >= '2' && local[0] <= '5'
}

// Hash calcula o identificador opaco de um número já normalizado.
func Hash(pepper []byte, e164 string) []byte {
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte(e164))
	return m.Sum(nil)
}
