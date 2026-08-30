package oauth

import (
	"net/url"
	"testing"
)

func TestMatchRedirectURI(t *testing.T) {
	registered := []string{
		"https://app.example.com/callback",
		"http://localhost:3000/callback",
	}

	t.Run("exact match passes", func(t *testing.T) {
		if !MatchRedirectURI(registered, "https://app.example.com/callback") {
			t.Fatal("expected exact match")
		}
	})
	t.Run("loopback different port passes", func(t *testing.T) {
		// OS-assigned port differs from the registered one.
		if !MatchRedirectURI(registered, "http://localhost:51234/callback") {
			t.Fatal("expected loopback port tolerance (RFC 8252 §7.3)")
		}
	})
	t.Run("non-loopback different port fails", func(t *testing.T) {
		if MatchRedirectURI(registered, "https://app.example.com:8443/callback") {
			t.Fatal("expected non-loopback port mismatch to fail")
		}
	})
	t.Run("non-loopback different host fails", func(t *testing.T) {
		if MatchRedirectURI(registered, "https://evil.example.com/callback") {
			t.Fatal("expected non-loopback host mismatch to fail")
		}
	})
	t.Run("loopback schemes must match", func(t *testing.T) {
		if MatchRedirectURI(registered, "https://localhost:3000/callback") {
			t.Fatal("expected http/https scheme mismatch on loopback to fail")
		}
	})
}

func TestIsLoopbackRedirectURI(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"http://localhost:3000/cb", true},
		{"http://127.0.0.1:1234/cb", true},
		{"http://[::1]:8080/cb", true},
		{"http://localhost/cb", true},
		{"https://app.example.com/cb", false},
	}
	for _, tc := range cases {
		u, _ := url.Parse(tc.raw)
		if got := IsLoopbackRedirectURI(u); got != tc.want {
			t.Fatalf("IsLoopbackRedirectURI(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
	if IsLoopbackRedirectURI(nil) {
		t.Fatal("expected nil URL to not be loopback")
	}
}

func TestAllowedClientRedirect(t *testing.T) {
	if !AllowedClientRedirect("https://app.example.com/callback") {
		t.Fatal("HTTPS callback should be allowed")
	}
	if !AllowedClientRedirect("http://localhost:3000/callback") {
		t.Fatal("loopback HTTP callback should be allowed")
	}
	if AllowedClientRedirect("http://app.example.com/callback") {
		t.Fatal("plain-HTTP non-loopback should be rejected")
	}
	if AllowedClientRedirect("not-a-url") {
		t.Fatal("malformed URI should be rejected")
	}
}
