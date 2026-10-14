package username

import "testing"

func TestNormalize(t *testing.T) {
	ok := map[string]string{"Maria": "maria", "@joao_silva": "joao_silva", "ana.b2": "ana.b2"}
	for in, want := range ok {
		if got, err := Normalize(in); err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; quero %q", in, got, err, want)
		}
	}
	for _, in := range []string{"ab", "1abc", "maria..silva", "maria.", "jo ão", "admin", "a234567890123456789012345678901234"} {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q; esperava erro", in, got)
		}
	}
}
