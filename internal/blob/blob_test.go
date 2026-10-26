package blob

import (
	"testing"
)

func TestParse(t *testing.T) {
	b, err := Parse([]byte(`{"dependencies":["0ad"],"minisigs":[]}`))
	if err != nil || b.Dependencies[0] != "0ad" {
		t.Fatal(err)
	}
}
