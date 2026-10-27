package audit

import "testing"

func TestEngineAdmits(t *testing.T) {
	if !EngineAdmits([]string{"0ad<=0.0.25"}, "0.0.24") {
		t.Fatal("1")
	}
	if EngineAdmits([]string{"0ad<=0.0.25"}, "0.0.26") {
		t.Fatal("2")
	}
	if !EngineAdmits([]string{"0ad>=0.0.27"}, "0.28.0") {
		t.Fatal("3")
	}
	if EngineAdmits([]string{"0ad=0.28"}, "0.28.0") {
		t.Fatal("4")
	}
	if !EngineAdmits([]string{"0ad=0.0.27"}, "0.0.27") {
		t.Fatal("5")
	}
	if !EngineAdmits([]string{"0ad"}, "0.28.0") {
		t.Fatal("6")
	}
}

func TestEngineGap(t *testing.T) {
	cases := []struct {
		deps []string
		want string
	}{
		{[]string{"0ad"}, ""},
		{[]string{"0ad>=0.0.26"}, ""},
		{[]string{"0ad=0.0.26"}, "outdated"},
		{[]string{"0ad>=0.0.26", "0ad<=0.0.27"}, "outdated"},
		{[]string{"0ad=0.27.0"}, "outdated"},
		{[]string{"0ad<0.28.0"}, "outdated"},
		{[]string{"0ad>=0.29.0", "0ad<0.30.0"}, "unreleased"},
		{[]string{"0ad>=0.28.0", "0ad<0.29.0"}, ""},
		{[]string{"0ad_extra=1.0", "0ad"}, ""},
	}
	for _, c := range cases {
		if got := EngineGap(c.deps, "0.28.0"); got != c.want {
			t.Errorf("%v: got %q, want %q", c.deps, got, c.want)
		}
	}
}
