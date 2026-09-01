package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsClientIDDocumentURL(t *testing.T) {
	r := NewCIMDResolver()
	cases := []struct {
		name     string
		clientID string
		want     bool
	}{
		{"empty", "", false},
		{"missing path", "https://claude.ai", false},
		{"root path", "https://claude.ai/", false},
		{"https with path", "https://claude.ai/oauth/.well-known/client-metadata", true},
		{"https with nested path", "https://vscode.dev/a/b", true},
		{"http loopback with path", "http://127.0.0.1:8080/md", true},
		{"http localhost with path", "http://localhost:8080/md", true},
		{"http non-loopback", "http://claude.ai/md", false},
		{"no scheme", "claude.ai/md", false},
		{"schema relative", "//claude.ai/md", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.IsClientIDDocumentURL(tc.clientID); got != tc.want {
				t.Fatalf("IsClientIDDocumentURL(%q) = %v, want %v", tc.clientID, got, tc.want)
			}
		})
	}
}

func TestResolveRejectsHostNotAllowlisted(t *testing.T) {
	r := NewCIMDResolver()
	// example.com is not in the default allowlist and is not loopback.
	_, err := r.Resolve(context.Background(), "https://example.com/md")
	if err == nil {
		t.Fatal("expected resolution of a non-allowlisted host to fail")
	}
	if !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveRejectsRedirect(t *testing.T) {
	var target *httptest.Server
	target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     target.URL + "/md",
			"redirect_uris": []string{"https://app/callback"},
		})
	}))
	defer target.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/md", http.StatusFound)
	}))
	defer server.Close()

	r := NewCIMDResolver()
	r.AllowHost("127.0.0.1")
	_, err := r.Resolve(context.Background(), server.URL+"/md")
	if err == nil {
		t.Fatal("expected redirect to be rejected")
	}
}

func TestResolve(t *testing.T) {
	fetches := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":                  "http://" + r.Host + "/md",
			"client_name":                "Claude for Work",
			"redirect_uris":              []string{"https://app/callback"},
			"token_endpoint_auth_method": "none",
		})
	}))
	defer server.Close()

	r := NewCIMDResolver()
	r.AllowHost("127.0.0.1")

	md, err := r.Resolve(context.Background(), server.URL+"/md")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if md.ClientID != server.URL+"/md" {
		t.Fatalf("ClientID = %q, want %q", md.ClientID, server.URL+"/md")
	}
	if md.ClientName != "Claude for Work" {
		t.Fatalf("ClientName = %q", md.ClientName)
	}
	if len(md.RedirectURIs) != 1 || md.RedirectURIs[0] != "https://app/callback" {
		t.Fatalf("RedirectURIs = %v", md.RedirectURIs)
	}
	if md.TokenEndpointAuthMethod != "none" {
		t.Fatalf("TokenEndpointAuthMethod = %q", md.TokenEndpointAuthMethod)
	}

	// A second call within the TTL must be served from cache.
	if _, err := r.Resolve(context.Background(), server.URL+"/md"); err != nil {
		t.Fatalf("cached Resolve failed: %v", err)
	}
	if fetches != 1 {
		t.Fatalf("expected document to be fetched once, got %d fetches", fetches)
	}
}

func TestResolveClientIDMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     "https://other.example/md",
			"redirect_uris": []string{"https://app/callback"},
		})
	}))
	defer server.Close()

	r := NewCIMDResolver()
	r.AllowHost("127.0.0.1")
	if _, err := r.Resolve(context.Background(), server.URL+"/md"); err == nil {
		t.Fatal("expected client_id mismatch to fail")
	}
}

func TestResolveNoRedirectURIs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id": "http://" + r.Host + "/md",
		})
	}))
	defer server.Close()

	r := NewCIMDResolver()
	r.AllowHost("127.0.0.1")
	if _, err := r.Resolve(context.Background(), server.URL+"/md"); err == nil {
		t.Fatal("expected missing redirect_uris to fail")
	}
}

func TestResolveUnsupportedAuthMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":                  "http://" + r.Host + "/md",
			"redirect_uris":              []string{"https://app/callback"},
			"token_endpoint_auth_method": "client_secret_basic",
		})
	}))
	defer server.Close()

	r := NewCIMDResolver()
	r.AllowHost("127.0.0.1")
	if _, err := r.Resolve(context.Background(), server.URL+"/md"); err == nil {
		t.Fatal("expected unsupported auth method to fail")
	}
}

func TestResolveNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer server.Close()

	r := NewCIMDResolver()
	r.AllowHost("127.0.0.1")
	if _, err := r.Resolve(context.Background(), server.URL+"/md"); err == nil {
		t.Fatal("expected non-200 to fail")
	}
}

func TestMetadataAdvertisesCIMDOnlyWhenResolverSet(t *testing.T) {
	store := newTestStore()
	cfg := DefaultConfig()
	cfg.Issuer = "https://as.example.com"

	// Without a resolver, the flag is omitted.
	as := NewAuthorizationServer(cfg, store)
	md := as.Metadata()
	if md.ClientIDMetadataDocumentSupported != nil {
		t.Fatalf("expected flag nil without resolver, got %v", *md.ClientIDMetadataDocumentSupported)
	}

	// With a resolver, the flag is advertised.
	as.WithCIMDResolver(NewCIMDResolver())
	md = as.Metadata()
	if md.ClientIDMetadataDocumentSupported == nil || !*md.ClientIDMetadataDocumentSupported {
		t.Fatal("expected CIMD to be advertised when resolver set")
	}
}

func TestValidateAuthorizeRequestResolvesCIMDClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     "http://" + r.Host + "/md",
			"redirect_uris": []string{"https://app/callback"},
		})
	}))
	defer server.Close()

	store := newTestStore()
	cfg := DefaultConfig()
	cfg.Issuer = "https://as.example.com"
	resolver := NewCIMDResolver()
	resolver.AllowHost("127.0.0.1")
	as := NewAuthorizationServer(cfg, store).WithCIMDResolver(resolver)

	req := AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            server.URL + "/md",
		RedirectURI:         "https://app/callback",
		CodeChallenge:       "abc123abc123abc123abc123abc123abc123abc123abc",
		CodeChallengeMethod: "S256",
	}
	if err := as.ValidateAuthorizeRequest(req); err != nil {
		t.Fatalf("expected CIMD client to authorize, got %v", err)
	}

	// A redirect_uri not in the resolved document must be rejected.
	req.RedirectURI = "https://evil.example/callback"
	if err := as.ValidateAuthorizeRequest(req); err == nil {
		t.Fatal("expected unmatched redirect_uri to be rejected")
	}
}

func TestRequireActiveClientAcceptsCIMDClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     "http://" + r.Host + "/md",
			"redirect_uris": []string{"https://app/callback"},
		})
	}))
	defer server.Close()

	store := newTestStore()
	cfg := DefaultConfig()
	cfg.Issuer = "https://as.example.com"
	resolver := NewCIMDResolver()
	resolver.AllowHost("127.0.0.1")
	as := NewAuthorizationServer(cfg, store).WithCIMDResolver(resolver)

	if err := as.requireActiveClient(server.URL + "/md"); err != nil {
		t.Fatalf("expected CIMD client to be active, got %v", err)
	}

	// Non-CIMD unknown client still fails.
	if err := as.requireActiveClient("client_nope"); err == nil {
		t.Fatal("expected unknown non-CIMD client to fail")
	}
}

func TestExchangeWithCIMDClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     "http://" + r.Host + "/md",
			"redirect_uris": []string{"https://app/callback"},
		})
	}))
	defer server.Close()

	store := newTestStore()
	cfg := DefaultConfig()
	cfg.Issuer = "https://as.example.com"
	resolver := NewCIMDResolver()
	resolver.AllowHost("127.0.0.1")
	as := NewAuthorizationServer(cfg, store).WithCIMDResolver(resolver)

	// Issue a code using the CIMD client_id.
	verifier := "abc123abc123abc123abc123abc123abc123abc123abc123abc123"
	challenge := base64.RawURLEncoding.EncodeToString(func() []byte {
		sum := sha256.Sum256([]byte(verifier))
		return sum[:]
	}())
	code, err := as.IssueAuthorizationCode(AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            server.URL + "/md",
		RedirectURI:         "https://app/callback",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}, 1)
	if err != nil {
		t.Fatalf("IssueAuthorizationCode: %v", err)
	}

	// Exchange requires the active-client kill-switch to pass for a CIMD id.
	resp, err := as.ExchangeCode(TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     server.URL + "/md",
		RedirectURI:  "https://app/callback",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected an access token")
	}
}
