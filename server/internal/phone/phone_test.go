package phone

import "testing"

func TestNormalize(t *testing.T) {
	valid := map[string]string{
		"+55 (11) 98765-4321": "+5511987654321",
		"11987654321":         "+5511987654321",
		"(21) 3456-7890":      "+552134567890",
		"0055 11 98765 4321":  "+5511987654321",
		"+1 415 555 2671":     "+14155552671",
		"+351 912 345 678":    "+351912345678",
	}
	for in, want := range valid {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; quero %q", in, got, err, want)
		}
	}

	invalid := []string{
		"",
		"abc",
		"12345",
		"+55 11 8765-43210", // celular sem o 9 inicial
		"+55 01 98765-4321", // DDD inválido
		"+55 11 1234-5678",  // fixo começando com 1
		"+1234567890123456", // longo demais
		"11 98765-4321; DROP",
	}
	for _, in := range invalid {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q; esperava erro", in, got)
		}
	}
}

func TestHashDependsOnPepper(t *testing.T) {
	a := Hash([]byte("a"), "+5511987654321")
	b := Hash([]byte("b"), "+5511987654321")
	if string(a) == string(b) {
		t.Fatal("hash deveria depender do pepper")
	}
}
