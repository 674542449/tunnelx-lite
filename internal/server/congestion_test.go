package server

import "testing"

func TestParseCongestion(t *testing.T) {
	for in, want := range map[string]bool{
		"cc=bbr": true, "cc=bbr-aggressive": true, "cc=brutal;rx=12500000": true,
		"cc=brutal": false, "cc=brutal;rx=10": false, "cc=brutal;rx=999999999999": false,
		"cc=reno": false, "": false, "rx=12500000": false,
	} {
		if _, _, ok := parseCongestion(in); ok != want {
			t.Errorf("%q: ok=%v, want %v", in, ok, want)
		}
	}
	if mode, rx, _ := parseCongestion("cc=brutal;rx=12500000"); mode != "brutal" || rx != 12500000 {
		t.Fatal(mode, rx)
	}
}
