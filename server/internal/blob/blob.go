// Package blob armazena os anexos cifrados em disco local, mantendo os dados
// sob controle de quem opera o servidor.
package blob

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

var ErrTooLarge = errors.New("anexo excede o tamanho máximo")

type FS struct {
	Dir string
}

func NewFS(dir string) (*FS, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FS{Dir: dir}, nil
}

func (f *FS) path(id uuid.UUID) string {
	s := id.String()
	return filepath.Join(f.Dir, s[:2], s)
}

// Put grava no máximo maxBytes de r e devolve o tamanho gravado.
func (f *FS) Put(id uuid.UUID, r io.Reader, maxBytes int64) (int64, error) {
	p := f.path(id)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".upload-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(r, maxBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	if n > maxBytes {
		return 0, ErrTooLarge
	}
	if n == 0 {
		return 0, fmt.Errorf("anexo vazio")
	}
	return n, os.Rename(tmp.Name(), p)
}

func (f *FS) Open(id uuid.UUID) (*os.File, error) {
	return os.Open(f.path(id))
}

func (f *FS) Delete(id uuid.UUID) error {
	err := os.Remove(f.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
