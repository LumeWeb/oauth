package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	t.Run("correct verifier passes", func(t *testing.T) {
		if !VerifyPKCE(verifier, challenge) {
			t.Fatal("expected valid verifier to pass")
		}
	})
	t.Run("wrong verifier fails", func(t *testing.T) {
		if VerifyPKCE("another-verifier", challenge) {
			t.Fatal("expected wrong verifier to fail")
		}
	})
	t.Run("empty challenge fails", func(t *testing.T) {
		if VerifyPKCE(verifier, "") {
			t.Fatal("expected empty challenge to fail")
		}
	})
	t.Run("empty verifier fails", func(t *testing.T) {
		if VerifyPKCE("", challenge) {
			t.Fatal("expected empty verifier to fail")
		}
	})
	t.Run("verifier shorter than RFC 7636 minimum rejected", func(t *testing.T) {
		if VerifyPKCE("short", challenge) {
			t.Fatal("expected sub-43-char verifier to be rejected")
		}
	})
	t.Run("verifier longer than RFC 7636 maximum rejected", func(t *testing.T) {
		long := strings.Repeat("A", 129)
		if VerifyPKCE(long, challenge) {
			t.Fatal("expected >128-char verifier to be rejected")
		}
	})
}

func TestValidBase64URL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"alnum", "ABCabc123", true},
		{"pkce chars", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", true},
		{"empty", "", false},
		{"markup angle", "<script>", false},
		{"plus slash", "ab+c/d==", false},
		{"space", "ab cd", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidBase64URL(tc.in); got != tc.want {
				t.Fatalf("ValidBase64URL(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
	// The RFC 7636 §4.1 example verifier must be valid.
	if !ValidBase64URL("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") {
		t.Fatal("RFC 7636 example verifier should be valid")
	}
	if strings.ContainsAny("dBjftJeZ4CVP", "+/=") {
		t.Fatal("base64url alphabet must exclude standard base64 chars")
	}
}
