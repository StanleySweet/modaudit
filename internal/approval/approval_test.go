package approval

import (
	"errors"
	"testing"
)

type fake struct {
	pass []byte
	line string
	err  error
}

func (f *fake) ReadPassword(prompt string) ([]byte, error) { return append([]byte(nil), f.pass...), f.err }
func (f *fake) ReadLine(prompt string) (string, error)      { return f.line, f.err }
func (f *fake) Println(string)                              {}
func (f *fake) Close() error                                 { return nil }

func TestConfirmExact(t *testing.T) {
	f := &fake{line: "ABC123"}
	ok, err := Confirm(f, []string{"x"}, "ABC123")
	if err != nil || !ok {
		t.Fatal(err, ok)
	}
	ok, err = Confirm(f, []string{"x"}, "")
	if err == nil || ok {
		t.Fatal("empty should error")
	}
	f2 := &fake{line: "abc123"}
	ok, _ = Confirm(f2, []string{"x"}, "ABC123")
	if ok {
		t.Fatal("case sensitive")
	}
	f3 := &fake{line: "ABC123 "}
	ok, _ = Confirm(f3, []string{"x"}, "ABC123")
	if ok {
		t.Fatal("spaces matter")
	}
	f4 := &fake{err: errors.New("e")}
	_, err = Confirm(f4, []string{"x"}, "ABC123")
	if err == nil {
		t.Fatal("read error")
	}
}
