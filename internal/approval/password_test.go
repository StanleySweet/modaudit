package approval

import (
	"testing"
)

func TestSplitArgs(t *testing.T) {
	args, err := splitArgs(`a "b c" 'd e'`)
	if err != nil || len(args) != 3 || args[0] != "a" || args[1] != "b c" || args[2] != "d e" {
		t.Fatalf("%v %v", args, err)
	}
	if _, err := splitArgs(`a "b`); err == nil {
		t.Fatal("should error")
	}
}

func TestPasswordCommand(t *testing.T) {
	f := &fake{}
	pass, err := Password(f, "/bin/sh -c 'printf secret'", "k.pem")
	if err != nil {
		t.Fatal(err)
	}
	if string(pass) != "secret" {
		t.Fatal(string(pass))
	}
	// failing command
	_, err = Password(f, "/bin/sh -c 'echo hi; exit 1'", "k.pem")
	if err == nil {
		t.Fatal("should fail")
	}
	if err.Error() == "" {
		t.Fatal("bad")
	}
}
