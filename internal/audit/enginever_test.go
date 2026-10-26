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
