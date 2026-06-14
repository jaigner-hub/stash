package cluster

import "testing"

func TestTokenRoundTrip(t *testing.T) {
	in := JoinToken{
		ClusterID: "abc123",
		LeaderAPI: "http://10.0.0.1:8200",
		Secret:    "deadbeef",
		UnsealKey: "c29tZS1iYXNlNjQta2V5",
	}
	enc, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeToken(enc)
	if err != nil {
		t.Fatal(err)
	}
	if *out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", *out, in)
	}
	if !out.HasKey() {
		t.Fatal("expected HasKey true")
	}
}

func TestTokenKeyless(t *testing.T) {
	in := JoinToken{ClusterID: "c", LeaderAPI: "http://h:8200", Secret: "s"}
	enc, _ := in.Encode()
	out, err := DecodeToken(enc)
	if err != nil {
		t.Fatal(err)
	}
	if out.HasKey() {
		t.Fatal("keyless token should not report HasKey")
	}
}

func TestDecodeRejectsJunk(t *testing.T) {
	for _, s := range []string{"", "nope", "stash1.!!!notbase64", "stash1." /* empty payload */} {
		if _, err := DecodeToken(s); err == nil {
			t.Fatalf("expected error decoding %q", s)
		}
	}
}

func TestDecodeRejectsIncomplete(t *testing.T) {
	// Valid base64 JSON but missing required fields.
	partial := JoinToken{ClusterID: "c"} // no LeaderAPI/Secret
	enc, _ := partial.Encode()
	if _, err := DecodeToken(enc); err == nil {
		t.Fatal("expected error for incomplete token")
	}
}

func TestAPIHostPort(t *testing.T) {
	cases := map[string]string{
		"http://10.0.0.1:8200":  "10.0.0.1:8200",
		"http://example.com":    "example.com:80",
		"https://example.com":   "example.com:443",
		"https://h.ts.net:8200": "h.ts.net:8200",
	}
	for in, want := range cases {
		got, err := APIHostPort(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Fatalf("%s: got %q want %q", in, got, want)
		}
	}
}
