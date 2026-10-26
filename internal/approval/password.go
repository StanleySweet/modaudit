package approval

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Password gets password from vault command or prompts.
func Password(t Terminal, cmd string, keyName string) ([]byte, error) {
	if cmd == "" {
		return t.ReadPassword("Password for " + keyName + ": ")
	}
	args, err := splitArgs(cmd)
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty password command")
	}
	c := exec.Command(args[0], args[1:]...)
	// attach stdin/stderr to terminal device
	if f, ok := t.(*tty); ok {
		c.Stdin = f.f
		c.Stderr = f.f
	} else {
		c.Stdin = os.Stdin
		c.Stderr = os.Stderr
	}
	out, err := c.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("password command failed: exit %d", ee.ExitCode())
		}
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty password")
	}
	out = bytes.TrimRight(out, "\n\r")
	if len(out) == 0 {
		return nil, fmt.Errorf("empty password")
	}
	return out, nil
}

func splitArgs(s string) ([]string, error) {
	var args []string
	var buf strings.Builder
	var quote rune
	for i := 0; i < len(s); i++ {
		ch := rune(s[i])
		if quote != 0 {
			if ch == quote {
				quote = 0
				continue
			}
			buf.WriteRune(ch)
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			continue
		}
		if ch == ' ' || ch == '\t' {
			if buf.Len() > 0 {
				args = append(args, buf.String())
				buf.Reset()
			}
			continue
		}
		buf.WriteRune(ch)
	}
	if quote != 0 {
		return nil, fmt.Errorf("unbalanced quote")
	}
	if buf.Len() > 0 {
		args = append(args, buf.String())
	}
	return args, nil
}
