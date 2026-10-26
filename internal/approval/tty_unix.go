//go:build !windows

package approval

import (
	"os"

	"golang.org/x/term"
)

// Open opens /dev/tty.
func Open() (Terminal, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, ErrNoTerminal
	}
	if !term.IsTerminal(int(f.Fd())) {
		f.Close()
		return nil, ErrNoTerminal
	}
	return &tty{f: f}, nil
}

type tty struct {
	f *os.File
}

func (t *tty) ReadPassword(prompt string) ([]byte, error) {
	t.f.WriteString(prompt)
	b, err := term.ReadPassword(int(t.f.Fd()))
	t.f.WriteString("\n")
	return b, err
}

func (t *tty) ReadLine(prompt string) (string, error) {
	t.f.WriteString(prompt)
	var buf []byte
	b := make([]byte, 1)
	for {
		n, err := t.f.Read(b)
		if n > 0 {
			if b[0] == '\n' {
				break
			}
			if b[0] == '\r' {
				// read next \n if present
				t.f.Read(make([]byte, 1))
				break
			}
			buf = append(buf, b[0])
		}
		if err != nil {
			return string(buf), err
		}
	}
	return string(buf), nil
}

func (t *tty) Println(s string) {
	t.f.WriteString(s + "\n")
}

func (t *tty) Close() error {
	return t.f.Close()
}
