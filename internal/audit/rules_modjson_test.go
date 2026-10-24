package audit

import "testing"

func TestModJSONRules(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"bad json", `{"name":"a"`, "MODJSON_INVALID"},
		{"missing field", `{"version":"1.0"}`, "MODJSON_MISSING_FIELD"},
		{"bad version", `{"name":"a","version":"banana","label":"A"}`, "MODJSON_VERSION_FORMAT"},
		{"ignore compat", `{"name":"a","version":"1.0","label":"A","ignoreInCompatibilityChecks":true}`, "COMPAT_IGNORE_FLAG"},
		{"name mismatch", `{"name":"wrong","version":"1.0","label":"A"}`, "MODJSON_NAME_MISMATCH"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Scan{Slug: "right", ModJSONRaw: []byte(c.raw)}
			rulesModJSON(s)
			if !hasCode(s.Findings, c.want) {
				t.Errorf("%s: got %+v", c.want, s.Findings)
			}
		})
	}
}

func TestModJSONUnknownFieldIsInfo(t *testing.T) {
	s := &Scan{ModJSONRaw: []byte(`{"name":"a","version":"1.0","label":"A","x_custom":1}`)}
	rulesModJSON(s)
	f := findCode(s.Findings, "MODJSON_UNKNOWN_FIELD")
	if f == nil || f.Severity != SeverityInfo {
		t.Fatalf("got %+v", s.Findings)
	}
}

func TestModJSONClean(t *testing.T) {
	s := &Scan{Slug: "mymod", ModJSONRaw: []byte(`{"name":"MyMod","version":"1.2.3","label":"My Mod"}`)}
	rulesModJSON(s)
	if len(s.Findings) != 0 {
		t.Fatalf("%+v", s.Findings)
	}
	if s.ModInfo.Version != "1.2.3" {
		t.Fatalf("%+v", s.ModInfo)
	}
}

func TestModJSONNumericOnly(t *testing.T) {
	for _, v := range []string{"1.2", "1.2.3", "10"} {
		s := &Scan{ModJSONRaw: []byte(`{"name":"a","version":"` + v + `","label":"A"}`)}
		rulesModJSON(s)
		if hasCode(s.Findings, "MODJSON_VERSION_FORMAT") {
			t.Fatalf("%s: %+v", v, s.Findings)
		}
	}
	for _, v := range []string{"1.2-beta", "v1.2", "2024-01-01", "1..2"} {
		s := &Scan{ModJSONRaw: []byte(`{"name":"a","version":"` + v + `","label":"A"}`)}
		rulesModJSON(s)
		if !hasCode(s.Findings, "MODJSON_VERSION_FORMAT") {
			t.Fatalf("%s: %+v", v, s.Findings)
		}
	}
}
