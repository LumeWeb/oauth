package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// clientMetaURL is the https URL used as the document URL in tests. It is only
// ever served by the fake RoundTripper, never dialed, so it does not need a
// resolvable host.
const clientMetaURL = "https://resolver.test/md"

// fakeRoundTripper returns canned responses, letting Resolve be exercised
// without outbound networking. Circulating PRs of this package run the SSRF
// gate (dialContext) separately so the tests stay deterministic.
type fakeRoundTripper struct {
	fn func(*http.Request) (*http.Response, error)
}

func (f fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f.fn(req)
}

// jsonResponse builds an *http.Response carrying body as JSON.
func jsonResponse(status int, body any) *http.Response {
	b, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(b)),
		Header:     make(http.Header),
	}
}

// fakeResolver returns a CIMDResolver whose fetches are served by rt instead
// of the SSRF-safe transport.
func fakeResolver(rt http.RoundTripper) *CIMDResolver {
	r := NewCIMDResolver()
	r.client.Transport = rt
	return r
}

// docResponse builds a valid metadata document whose client_id matches the
// request the transport is serving.
func docResponse() *http.Response {
	return jsonResponse(http.StatusOK, map[string]any{
		"client_id":                  clientMetaURL,
		"client_name":                "Claude for Work",
		"redirect_uris":              []string{"https://app/callback"},
		"token_endpoint_auth_method": "none",
	})
}

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
		{"https with nested path", "https://resolver.test/a/b", true},
		{"http with path", "http://resolver.test/md", false},
		{"no scheme", "resolver.test/md", false},
		{"schema relative", "//resolver.test/md", false},
		{"empty host", "https:///md", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.IsClientIDDocumentURL(tc.clientID); got != tc.want {
				t.Fatalf("IsClientIDDocumentURL(%q) = %v, want %v", tc.clientID, got, tc.want)
			}
		})
	}
}

// TestResolveOpenByDefault is the canonical regression guard for the CIMD
// redesign: with no AllowHost call the allowlist is empty, which means the
// resolver must accept any public https URL rather than refusing it.
func TestResolveOpenByDefault(t *testing.T) {
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return docResponse(), nil
	}})

	md, err := r.Resolve(context.Background(), clientMetaURL)
	if err != nil {
		t.Fatalf("expected empty allowlist to be open, got %v", err)
	}
	if md.ClientID != clientMetaURL {
		t.Fatalf("ClientID = %q, want %q", md.ClientID, clientMetaURL)
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
}

func TestResolveAllowlistRestricts(t *testing.T) {
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return docResponse(), nil
	}})
	r.AllowHost("allowed.test")

	if _, err := r.Resolve(context.Background(), "https://blocked.test/md"); err == nil {
		t.Fatal("expected a host outside the allowlist to be rejected")
	} else if !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("unexpected error: %v", err)
	}

	// The allowlisted host still resolves.
	r.client.Transport = fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, map[string]any{
			"client_id":     "https://allowed.test/md",
			"redirect_uris": []string{"https://app/callback"},
		}), nil
	}}
	md, err := r.Resolve(context.Background(), "https://allowed.test/md")
	if err != nil {
		t.Fatalf("expected allowlisted host to resolve, got %v", err)
	}
	if md.ClientID != "https://allowed.test/md" {
		t.Fatalf("ClientID = %q", md.ClientID)
	}
}

func TestResolveCaches(t *testing.T) {
	var fetches atomic.Int32
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		fetches.Add(1)
		return docResponse(), nil
	}})

	for i := 0; i < 2; i++ {
		if _, err := r.Resolve(context.Background(), clientMetaURL); err != nil {
			t.Fatalf("Resolve failed: %v", err)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("expected document to be fetched once, got %d fetches", got)
	}
}

func TestResolveRejectsNonHTTPS(t *testing.T) {
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return docResponse(), nil
	}})
	for _, id := range []string{"http://resolver.test/md", "ftp://resolver.test/md", "resolver.test/md"} {
		if _, err := r.Resolve(context.Background(), id); err == nil {
			t.Fatalf("expected non-https URL %q to be rejected", id)
		}
	}
}

func TestResolveRejectsRedirect(t *testing.T) {
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		resp := jsonResponse(http.StatusFound, nil)
		resp.Header.Set("Location", "https://evil.test/callback")
		return resp, nil
	}})
	if _, err := r.Resolve(context.Background(), clientMetaURL); err == nil {
		t.Fatal("expected a redirect to be rejected")
	}
}

func TestResolveClientIDMismatch(t *testing.T) {
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, map[string]any{
			"client_id":     "https://other.example/md",
			"redirect_uris": []string{"https://app/callback"},
		}), nil
	}})
	if _, err := r.Resolve(context.Background(), clientMetaURL); err == nil {
		t.Fatal("expected client_id mismatch to fail")
	}
}

func TestResolveNoRedirectURIs(t *testing.T) {
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, map[string]any{"client_id": clientMetaURL}), nil
	}})
	if _, err := r.Resolve(context.Background(), clientMetaURL); err == nil {
		t.Fatal("expected missing redirect_uris to fail")
	}
}

// TestResolveAcceptsAnyAuthMethod is the regression guard for the relaxed
// CIMD gate: whatever token_endpoint_auth_method a client declares (RFC 7591
// §3.2.1) is accepted instead of rejected, and the declared value is preserved
// in the resolved metadata.
func TestResolveAcceptsAnyAuthMethod(t *testing.T) {
	for _, method := range []string{
		"none",
		"client_secret_basic",
		"client_secret_post",
		"client_secret_jwt",
		"private_key_jwt",
		"tls_client_auth",
		"self_signed_tls_client_auth",
		"custom_method",
	} {
		t.Run(method, func(t *testing.T) {
			r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, map[string]any{
					"client_id":                  clientMetaURL,
					"redirect_uris":              []string{"https://app/callback"},
					"token_endpoint_auth_method": method,
				}), nil
			}})
			md, err := r.Resolve(context.Background(), clientMetaURL)
			if err != nil {
				t.Fatalf("expected declared auth method %q to be accepted, got %v", method, err)
			}
			if md.TokenEndpointAuthMethod != method {
				t.Fatalf("TokenEndpointAuthMethod = %q, want %q (declared method must be preserved)", md.TokenEndpointAuthMethod, method)
			}
		})
	}
}

// TestResolveAcceptsPrivateKeyJWT covers the ChatGPT client metadata document
// (https://chatgpt.com/.well-known/oauth-client-configuration), which declares
// token_endpoint_auth_method "private_key_jwt" and was previously rejected by
// the CIMD gate.
func TestResolveAcceptsPrivateKeyJWT(t *testing.T) {
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, map[string]any{
			"client_id":                  clientMetaURL,
			"client_name":                "ChatGPT",
			"redirect_uris":              []string{"https://chatgpt.com/oauth/callback"},
			"token_endpoint_auth_method": "private_key_jwt",
		}), nil
	}})
	md, err := r.Resolve(context.Background(), clientMetaURL)
	if err != nil {
		t.Fatalf("expected private_key_jwt document to resolve, got %v", err)
	}
	if md.TokenEndpointAuthMethod != "private_key_jwt" {
		t.Fatalf("TokenEndpointAuthMethod = %q, want %q", md.TokenEndpointAuthMethod, "private_key_jwt")
	}
	if md.ClientName != "ChatGPT" {
		t.Fatalf("ClientName = %q, want %q", md.ClientName, "ChatGPT")
	}
}

// TestResolveEmptyAuthMethodDefaultsToNone asserts that a document omitting
// token_endpoint_auth_method resolves with the RFC 7591 default of "none".
func TestResolveEmptyAuthMethodDefaultsToNone(t *testing.T) {
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, map[string]any{
			"client_id":     clientMetaURL,
			"redirect_uris": []string{"https://app/callback"},
		}), nil
	}})
	md, err := r.Resolve(context.Background(), clientMetaURL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if md.TokenEndpointAuthMethod != "none" {
		t.Fatalf("TokenEndpointAuthMethod = %q, want %q", md.TokenEndpointAuthMethod, "none")
	}
}

func TestResolveNon200(t *testing.T) {
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusNotFound, nil), nil
	}})
	if _, err := r.Resolve(context.Background(), clientMetaURL); err == nil {
		t.Fatal("expected non-200 to fail")
	}
}

func TestResolveInvalidJSON(t *testing.T) {
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("not json")),
			Header:     make(http.Header),
		}, nil
	}})
	if _, err := r.Resolve(context.Background(), clientMetaURL); err == nil {
		t.Fatal("expected invalid JSON to fail")
	}
}

func TestIsPublicRoutableIP(t *testing.T) {
	public := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34",
	}
	private := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"100.64.0.1",
		"198.18.0.1",
		"127.0.0.1",
		"169.254.169.254",
		"0.0.0.0",
		"224.0.0.1",
	}
	for _, s := range public {
		if !isPublicRoutableIP(net.ParseIP(s)) {
			t.Fatalf("expected %s to be publicly routable", s)
		}
	}
	for _, s := range private {
		if isPublicRoutableIP(net.ParseIP(s)) {
			t.Fatalf("expected %s to be refused as non-public", s)
		}
	}
	if isPublicRoutableIP(nil) {
		t.Fatal("expected nil IP to be refused")
	}
}

// TestDialContextRefusesNonPublicIP exercises the SSRF gate's connection
// decision: a host that resolves only to non-public addresses must not be
// dialable, regardless of the allowlist.
func TestDialContextRefusesNonPublicIP(t *testing.T) {
	nonPublic := []string{"127.0.0.1", "10.0.0.1", "169.254.169.254"}
	for _, ip := range nonPublic {
		r := NewCIMDResolver()
		r.lookupAddr = func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
		}
		conn, err := r.dialContext(context.Background(), "tcp", "host:443")
		if err == nil {
			conn.Close()
			t.Fatalf("expected dial of %s to be refused", ip)
		}
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
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return docResponse(), nil
	}})

	store := newTestStore()
	cfg := DefaultConfig()
	cfg.Issuer = "https://as.example.com"
	as := NewAuthorizationServer(cfg, store).WithCIMDResolver(r)

	req := AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            clientMetaURL,
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
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return docResponse(), nil
	}})

	store := newTestStore()
	cfg := DefaultConfig()
	cfg.Issuer = "https://as.example.com"
	as := NewAuthorizationServer(cfg, store).WithCIMDResolver(r)

	if err := as.requireActiveClient(clientMetaURL); err != nil {
		t.Fatalf("expected CIMD client to be active, got %v", err)
	}

	// Non-CIMD unknown client still fails.
	if err := as.requireActiveClient("client_nope"); err == nil {
		t.Fatal("expected unknown non-CIMD client to fail")
	}
}

func TestExchangeWithCIMDClient(t *testing.T) {
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return docResponse(), nil
	}})

	store := newTestStore()
	cfg := DefaultConfig()
	cfg.Issuer = "https://as.example.com"
	as := NewAuthorizationServer(cfg, store).WithCIMDResolver(r)

	verifier := "abc123abc123abc123abc123abc123abc123abc123abc123abc123"
	challenge := base64.RawURLEncoding.EncodeToString(func() []byte {
		sum := sha256.Sum256([]byte(verifier))
		return sum[:]
	}())
	code, err := as.IssueAuthorizationCode(AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            clientMetaURL,
		RedirectURI:         "https://app/callback",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}, 1)
	if err != nil {
		t.Fatalf("IssueAuthorizationCode: %v", err)
	}

	resp, err := as.ExchangeCode(TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     clientMetaURL,
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

func TestClientMetadataReturnsCIMDName(t *testing.T) {
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return docResponse(), nil
	}})

	store := newTestStore()
	cfg := DefaultConfig()
	cfg.Issuer = "https://as.example.com"
	as := NewAuthorizationServer(cfg, store).WithCIMDResolver(r)

	client, err := as.ClientMetadata(clientMetaURL)
	if err != nil {
		t.Fatalf("ClientMetadata: %v", err)
	}
	if client.ClientName != "Claude for Work" {
		t.Fatalf("ClientName = %q, want %q (client_name must flow from the CIMD document)", client.ClientName, "Claude for Work")
	}
	if client.ClientID != clientMetaURL {
		t.Fatalf("ClientID = %q, want %q", client.ClientID, clientMetaURL)
	}
	if client.ClientURI != clientMetaURL {
		t.Fatalf("ClientURI = %q, want %q (CIMD document URL must flow into the client)", client.ClientURI, clientMetaURL)
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != "https://app/callback" {
		t.Fatalf("RedirectURIs = %v", client.RedirectURIs)
	}
	if !client.IsActive {
		t.Fatal("expected CIMD-resolved client to be active")
	}
}

func TestLookupCIMDPersistsAndSkipsRefetch(t *testing.T) {
	fetches := 0
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		fetches++
		return docResponse(), nil
	}})

	store := newTestStore()
	cfg := DefaultConfig()
	cfg.Issuer = "https://as.example.com"
	as := NewAuthorizationServer(cfg, store).WithCIMDResolver(r)

	client, err := as.ClientMetadata(clientMetaURL)
	if err != nil {
		t.Fatalf("first ClientMetadata: %v", err)
	}
	if client.ClientURI != clientMetaURL {
		t.Fatalf("ClientURI = %q, want %q", client.ClientURI, clientMetaURL)
	}
	// The resolved client must be persisted (with its URI) to the store.
	got, err := store.GetClient(clientMetaURL)
	if err != nil {
		t.Fatalf("expected CIMD client persisted to store: %v", err)
	}
	if got.ClientURI != clientMetaURL || !got.IsActive {
		t.Fatalf("persisted client mismatch: %+v", got)
	}
	if fetches != 1 {
		t.Fatalf("fetches after first lookup = %d, want 1", fetches)
	}

	// A second lookup resolves again, but the resolver's TTL cache serves it
	// without hitting the network (no additional fetch) and re-persists as a
	// no-op upsert.
	if _, err := as.ClientMetadata(clientMetaURL); err != nil {
		t.Fatalf("second ClientMetadata: %v", err)
	}
	if fetches != 1 {
		t.Fatalf("fetches after cached lookup = %d, want 1 (resolver cache must absorb it)", fetches)
	}
}

func TestLookupCIMDPersistsOnlyWhenChanged(t *testing.T) {
	r := fakeResolver(fakeRoundTripper{fn: func(_ *http.Request) (*http.Response, error) {
		return docResponse(), nil
	}})

	store := newTestStore()
	cfg := DefaultConfig()
	cfg.Issuer = "https://as.example.com"
	as := NewAuthorizationServer(cfg, store).WithCIMDResolver(r)

	// Seed the store with a stale CIMD client that differs from the document
	// (e.g. an earlier rotation already re-resolved it).
	stale := Client{
		ClientID:     clientMetaURL,
		ClientURI:    clientMetaURL,
		ClientName:   "Stale",
		RedirectURIs: []string{"https://old/callback"},
		IsActive:     true,
	}
	if err := store.SaveClient(stale); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if store.saveClientCalls != 1 {
		t.Fatalf("saveClientCalls after seed = %d, want 1", store.saveClientCalls)
	}

	// First lookup re-resolves and the resolved client differs from the stale
	// copy, so it must persist the update.
	if _, err := as.ClientMetadata(clientMetaURL); err != nil {
		t.Fatalf("first ClientMetadata: %v", err)
	}
	if store.saveClientCalls != 2 {
		t.Fatalf("saveClientCalls after changed lookup = %d, want 2 (must persist update)", store.saveClientCalls)
	}

	// A TTL-cached lookup now matches the stored copy, so it must not write.
	if _, err := as.ClientMetadata(clientMetaURL); err != nil {
		t.Fatalf("cached ClientMetadata: %v", err)
	}
	if store.saveClientCalls != 2 {
		t.Fatalf("saveClientCalls after cached lookup = %d, want 2 (must skip redundant write)", store.saveClientCalls)
	}
}
