package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"sync"
	"testing"
)

func TestSetIssuer(t *testing.T) {
	s := testServer()
	if got := s.Config().Issuer; got != "https://auth.example.com" {
		t.Fatalf("expected default issuer https://auth.example.com, got %q", got)
	}

	t.Run("valid url updates issuer and expected resource", func(t *testing.T) {
		if err := s.SetIssuer("https://mcp.example.com/mcp"); err != nil {
			t.Fatalf("SetIssuer returned error: %v", err)
		}
		if got, want := s.Config().Issuer, "https://mcp.example.com/mcp"; got != want {
			t.Fatalf("issuer = %q, want %q", got, want)
		}
		if got, want := s.expectedResource(), "https://mcp.example.com/mcp"; got != want {
			t.Fatalf("expectedResource = %q, want %q", got, want)
		}
	})

	t.Run("invalid issuer leaves previous value untouched", func(t *testing.T) {
		if err := s.SetIssuer("not a url"); err == nil {
			t.Fatal("expected error for invalid issuer")
		}
		if got, want := s.Config().Issuer, "https://mcp.example.com/mcp"; got != want {
			t.Fatalf("issuer changed to %q after failed SetIssuer, want %q", got, want)
		}
	})

	t.Run("http issuer on non-loopback rejected", func(t *testing.T) {
		if err := s.SetIssuer("http://public.example.com"); err == nil {
			t.Fatal("expected error for non-loopback http issuer")
		}
	})

	t.Run("loopback http issuer allowed", func(t *testing.T) {
		if err := s.SetIssuer("http://localhost:8080"); err != nil {
			t.Fatalf("expected loopback http issuer to be accepted: %v", err)
		}
	})

	t.Run("*.localhost http issuer allowed", func(t *testing.T) {
		if err := s.SetIssuer("http://account.localhost"); err != nil {
			t.Fatalf("expected *.localhost http issuer to be accepted: %v", err)
		}
	})

	t.Run("localhost-suffixed non-loopback host rejected", func(t *testing.T) {
		if err := s.SetIssuer("http://evil.localhost.example.com"); err == nil {
			t.Fatal("expected http issuer on a host merely suffixing localhost to be rejected")
		}
	})
}

func TestIsLoopbackURI(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"http://localhost", true},
		{"http://localhost:8080", true},
		{"http://127.0.0.1", true},
		{"http://127.0.0.1:8080", true},
		{"http://[::1]:8080", true},
		{"http://account.localhost", true},
		{"http://a.b.localhost:9000", true},
		{"http://localhost.example.com", false},
		{"http://evil.localhost.example.com", false},
		{"http://example.com", false},
	}
	for _, tc := range cases {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.raw, err)
		}
		if got := IsLoopbackURI(u); got != tc.want {
			t.Fatalf("IsLoopbackURI(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
	if IsLoopbackURI(nil) {
		t.Fatal("expected nil URL to not be loopback")
	}
}

func TestSetIssuerDrivesResourceValidation(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)

	req := validAuthorizeRequest(client.ClientID, redirect)
	// Bind a resource that matches once the issuer is re-pointed.
	req.Resource = "https://mcp.example.com/mcp"

	if err := s.SetIssuer("https://mcp.example.com/mcp"); err != nil {
		t.Fatalf("SetIssuer returned error: %v", err)
	}
	if err := s.ValidateAuthorizeRequest(req); err != nil {
		t.Fatalf("expected request bound to the new resource to pass: %v", err)
	}

	req.Resource = "https://other.example.com/mcp"
	var oerr *OAuthError
	if err := s.ValidateAuthorizeRequest(req); err == nil || !errors.As(err, &oerr) || oerr.Code != ErrInvalidRequest {
		t.Fatalf("expected invalid_request for mismatched resource, got %v", err)
	}
}

// TestSetIssuerConcurrentReconfiguration runs under -race to guard against a
// data race between SetIssuer (write) and expectedResource reads performed by
// ValidateAuthorizeRequest (regression for the RWMutex guard on cfg.Issuer).
func TestSetIssuerConcurrentReconfiguration(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)
	req := validAuthorizeRequest(client.ClientID, redirect)
	req.Resource = "https://mcp.example.com/mcp"

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			s.expectedResource()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = s.SetIssuer("https://mcp.example.com/mcp")
			s.ValidateAuthorizeRequest(req)
		}
	}()
	wg.Wait()
}

// validAuthorizeRequest builds a well-formed authorize request for the given
// client and redirect using the RFC 7636 test verifier.
func validAuthorizeRequest(clientID, redirect string) AuthorizeRequest {
	sum := sha256.Sum256([]byte(testVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            clientID,
		RedirectURI:         redirect,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}
}
