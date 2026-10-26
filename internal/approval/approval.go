package approval

import (
	"errors"
	"strings"
)

var ErrNoTerminal = errors.New("no terminal")

// Terminal is the controlling terminal.
type Terminal interface {
	ReadPassword(prompt string) ([]byte, error)
	ReadLine(prompt string) (string, error)
	Println(string)
	Close() error
}

// Confirm prompts for exact token match.
func Confirm(t Terminal, summary []string, token string) (bool, error) {
	if token == "" {
		return false, errors.New("empty token")
	}
	for _, s := range summary {
		t.Println(s)
	}
	t.Println("Type: " + token)
	line, err := t.ReadLine("Confirm: ")
	if err != nil {
		return false, err
	}
	// trim line ending
	line = strings.TrimRight(line, "\r\n")
	return line == token, nil
}
