package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func testServer() *AuthorizationServer {
	cfg := DefaultConfig()
	cfg.Issuer = "https://auth.example.com"
	return NewAuthorizationServer(cfg, newTestStore())
}

// RFC 7636 §4.1 example verifier — exactly 43 chars, so VerifyPKCE's length
// gate accepts it.
const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// A distinct verifier of valid length used where a mismatch is expected.
const testWrongVerifier = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

func mustRegisterClient(t *testing.T, s *AuthorizationServer, redirect string) *Client {
	t.Helper()
	client, err := s.RegisterClient(ClientRegistration{
		ClientName:   "test",
		RedirectURIs: []string{redirect},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	return client
}

func mustIssueCode(t *testing.T, s *AuthorizationServer, clientID, redirect, verifier string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	code, err := s.IssueAuthorizationCode(AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            clientID,
		RedirectURI:         redirect,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}, 42)
	if err != nil {
		t.Fatalf("issue code: %v", err)
	}
	return code
}

func TestRegisterClientDefaults(t *testing.T) {
	s := testServer()
	client, err := s.RegisterClient(ClientRegistration{
		ClientName:   "web",
		RedirectURIs: []string{"https://app.example.com/cb"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if client.ClientID == "" {
		t.Fatal("expected a generated client_id")
	}
	if len(client.GrantTypes) != 2 || client.GrantTypes[0] != "authorization_code" {
		t.Fatalf("unexpected grant types: %v", client.GrantTypes)
	}
	if client.TokenEndpointAuth != "none" {
		t.Fatalf("token auth method = %q, want none", client.TokenEndpointAuth)
	}
	if !client.IsActive {
		t.Fatal("expected client active")
	}
}

func TestRegisterClientRejectsBadRedirect(t *testing.T) {
	s := testServer()
	if _, err := s.RegisterClient(ClientRegistration{
		RedirectURIs: []string{"http://evil.example.com/cb"},
	}); err == nil {
		t.Fatal("expected plain-HTTP non-loopback redirect to be rejected")
	}
}

func TestValidateAuthorizeRequest(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)

	verifier := "verifier-1234567890"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	valid := AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            client.ClientID,
		RedirectURI:         redirect,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}

	t.Run("valid passes", func(t *testing.T) {
		if err := s.ValidateAuthorizeRequest(valid); err != nil {
			t.Fatalf("expected valid request to pass: %v", err)
		}
	})
	t.Run("wrong response type", func(t *testing.T) {
		req := valid
		req.ResponseType = "token"
		if err := s.ValidateAuthorizeRequest(req); err == nil {
			t.Fatal("expected failure")
		}
	})
	t.Run("unknown client", func(t *testing.T) {
		req := valid
		req.ClientID = "nope"
		if err := s.ValidateAuthorizeRequest(req); err == nil {
			t.Fatal("expected failure")
		}
	})
	t.Run("mismatched redirect", func(t *testing.T) {
		req := valid
		req.RedirectURI = "https://evil.example.com/cb"
		if err := s.ValidateAuthorizeRequest(req); err == nil {
			t.Fatal("expected failure")
		}
	})
	t.Run("missing pkce", func(t *testing.T) {
		req := valid
		req.CodeChallenge = ""
		if err := s.ValidateAuthorizeRequest(req); err == nil {
			t.Fatal("expected failure")
		}
	})
	t.Run("non-S256 pkce", func(t *testing.T) {
		req := valid
		req.CodeChallengeMethod = "plain"
		if err := s.ValidateAuthorizeRequest(req); err == nil {
			t.Fatal("expected failure")
		}
	})
	t.Run("bad code challenge alphabet", func(t *testing.T) {
		req := valid
		req.CodeChallenge = "has spaces here"
		if err := s.ValidateAuthorizeRequest(req); err == nil {
			t.Fatal("expected failure")
		}
	})
	t.Run("invalid resource binding", func(t *testing.T) {
		req := valid
		req.Resource = "https://evil.example.com/api"
		if err := s.ValidateAuthorizeRequest(req); err == nil {
			t.Fatal("expected failure")
		}
	})
}

func TestExchangeCodeFlow(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	code := mustIssueCode(t, s, client.ClientID, redirect, verifier)

	resp, err := s.ExchangeCode(TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     client.ClientID,
		RedirectURI:  redirect,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatal("expected access and refresh tokens")
	}
	if resp.TokenType != "Bearer" {
		t.Fatalf("token type = %q, want Bearer", resp.TokenType)
	}

	t.Run("access token validates with bound userID", func(t *testing.T) {
		userID, _, ok := s.ValidateAccessToken(resp.AccessToken)
		if !ok {
			t.Fatal("expected access token valid")
		}
		if userID != 42 {
			t.Fatalf("userID = %d, want 42", userID)
		}
	})

	t.Run("code is single-use", func(t *testing.T) {
		if _, err := s.ExchangeCode(TokenRequest{
			Code:         code,
			ClientID:     client.ClientID,
			RedirectURI:  redirect,
			CodeVerifier: verifier,
		}); err == nil {
			t.Fatal("expected second redemption to fail")
		}
	})
}

func TestExchangeCodeRejectsWrongVerifier(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)
	code := mustIssueCode(t, s, client.ClientID, redirect, testVerifier)

	_, err := s.ExchangeCode(TokenRequest{
		Code:         code,
		ClientID:     client.ClientID,
		RedirectURI:  redirect,
		CodeVerifier: testWrongVerifier,
	})
	if err == nil {
		t.Fatal("expected wrong verifier to fail")
	}
}

func TestRefreshTokenFlow(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)
	verifier := testVerifier
	code := mustIssueCode(t, s, client.ClientID, redirect, verifier)

	resp, err := s.ExchangeCode(TokenRequest{
		Code:         code,
		ClientID:     client.ClientID,
		RedirectURI:  redirect,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	refreshed, err := s.RefreshToken(TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: resp.RefreshToken,
		ClientID:     client.ClientID,
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Fatal("expected a new access/refresh pair")
	}
	if refreshed.RefreshToken == resp.RefreshToken {
		t.Fatal("refresh token must rotate")
	}

	t.Run("userID carried through rotation", func(t *testing.T) {
		userID, _, ok := s.ValidateAccessToken(refreshed.AccessToken)
		if !ok {
			t.Fatal("expected refreshed access token valid")
		}
		if userID != 42 {
			t.Fatalf("userID after refresh = %d, want 42 (identity lost on rotation)", userID)
		}
	})

	t.Run("old refresh token re-presented in window is a benign reuse", func(t *testing.T) {
		// Within the reuse window this is tolerated (client had not yet
		// persisted the successor), not treated as a replay.
		again, err := s.RefreshToken(TokenRequest{
			RefreshToken: resp.RefreshToken,
			ClientID:     client.ClientID,
		})
		if err != nil {
			t.Fatalf("expected in-window reuse accepted: %v", err)
		}
		if again.RefreshToken != refreshed.RefreshToken {
			t.Fatalf("expected same rotated successor, got %q", again.RefreshToken)
		}
	})

	t.Run("unknown refresh token yields invalid_grant", func(t *testing.T) {
		_, err := s.RefreshToken(TokenRequest{
			RefreshToken: "no-such-token",
			ClientID:     client.ClientID,
		})
		oe, ok := err.(*OAuthError)
		if !ok || oe.Code != ErrInvalidGrant {
			t.Fatalf("expected invalid_grant, got %v", err)
		}
	})
}

func TestValidateAccessTokenUnknown(t *testing.T) {
	s := testServer()
	if _, _, ok := s.ValidateAccessToken("unknown-token"); ok {
		t.Fatal("expected unknown token invalid")
	}
}

func TestRevokeToken(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)
	code := mustIssueCode(t, s, client.ClientID, redirect, testVerifier)

	resp, err := s.ExchangeCode(TokenRequest{
		Code:         code,
		ClientID:     client.ClientID,
		RedirectURI:  redirect,
		CodeVerifier: testVerifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if err := s.RevokeToken(resp.AccessToken); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, ok := s.ValidateAccessToken(resp.AccessToken); ok {
		t.Fatal("expected revoked access token invalid")
	}
	// Revoking an unknown token is not an error (RFC 7009 idempotence).
	if err := s.RevokeToken("not-a-token"); err != nil {
		t.Fatalf("revoke unknown: %v", err)
	}
}

func TestExpiredAccessTokenRejectedAndPurged(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)
	code := mustIssueCode(t, s, client.ClientID, redirect, testVerifier)

	resp, err := s.ExchangeCode(TokenRequest{
		Code:         code,
		ClientID:     client.ClientID,
		RedirectURI:  redirect,
		CodeVerifier: testVerifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	// Backdate past the clock-skew grace.
	ts := s.store.(*testStore)
	at := ts.accessTokens[resp.AccessToken]
	at.ExpiresAt = time.Now().Add(-time.Hour)
	ts.accessTokens[resp.AccessToken] = at

	if _, _, ok := s.ValidateAccessToken(resp.AccessToken); ok {
		t.Fatal("expected expired access token invalid")
	}
	if _, err := s.store.GetAccessToken(resp.AccessToken); err == nil {
		t.Fatal("expected expired token purged on validation")
	}
}

func TestReap(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)
	code := mustIssueCode(t, s, client.ClientID, redirect, testVerifier)

	if _, err := s.ExchangeCode(TokenRequest{
		Code:         code,
		ClientID:     client.ClientID,
		RedirectURI:  redirect,
		CodeVerifier: testVerifier,
	}); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if err := s.Reap(); err != nil {
		t.Fatalf("reap: %v", err)
	}
	// Nothing should error even though entries were visited.
}

func TestInactiveClientRejected(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)

	// Deactivate the client behind the server's back (consumer kill-switch).
	ts := s.store.(*testStore)
	ts.mu.Lock()
	c := ts.clients[client.ClientID]
	c.IsActive = false
	ts.clients[client.ClientID] = c
	ts.mu.Unlock()

	sum := sha256.Sum256([]byte(testVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if err := s.ValidateAuthorizeRequest(AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            client.ClientID,
		RedirectURI:         redirect,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}); err == nil {
		t.Fatal("expected inactive client to be rejected")
	}
}

func TestRevokeRefreshChain(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)
	code := mustIssueCode(t, s, client.ClientID, redirect, testVerifier)

	resp, err := s.ExchangeCode(TokenRequest{
		Code:         code,
		ClientID:     client.ClientID,
		RedirectURI:  redirect,
		CodeVerifier: testVerifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if err := s.RevokeToken(resp.RefreshToken); err != nil {
		t.Fatalf("revoke refresh chain: %v", err)
	}
	_, err = s.RefreshToken(TokenRequest{
		RefreshToken: resp.RefreshToken,
		ClientID:     client.ClientID,
	})
	oe, ok := err.(*OAuthError)
	if !ok || oe.Code != ErrInvalidGrant {
		t.Fatalf("expected revoked refresh chain to yield invalid_grant, got %v", err)
	}
}

func TestRefreshTokenEmptyClientIDTolerated(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)
	code := mustIssueCode(t, s, client.ClientID, redirect, testVerifier)

	resp, err := s.ExchangeCode(TokenRequest{
		Code:         code,
		ClientID:     client.ClientID,
		RedirectURI:  redirect,
		CodeVerifier: testVerifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	// Empty client_id on refresh is tolerated (matches reference) and must
	// still resolve the bound client for the active-kill-switch.
	refreshed, err := s.RefreshToken(TokenRequest{
		RefreshToken: resp.RefreshToken,
	})
	if err != nil {
		t.Fatalf("refresh with empty client_id: %v", err)
	}
	if userID, _, ok := s.ValidateAccessToken(refreshed.AccessToken); !ok || userID != 42 {
		t.Fatalf("expected refreshed token with userID 42, got ok=%v userID=%d", ok, userID)
	}
}

func TestInactiveClientBlocksTokenExchange(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)
	code := mustIssueCode(t, s, client.ClientID, redirect, testVerifier)

	// Deactivate after the code was issued (kill-switch mid-grant).
	ts := s.store.(*testStore)
	ts.mu.Lock()
	c := ts.clients[client.ClientID]
	c.IsActive = false
	ts.clients[client.ClientID] = c
	ts.mu.Unlock()

	_, err := s.ExchangeCode(TokenRequest{
		Code:         code,
		ClientID:     client.ClientID,
		RedirectURI:  redirect,
		CodeVerifier: testVerifier,
	})
	oe, ok := err.(*OAuthError)
	if !ok || oe.Code != ErrInvalidGrant {
		t.Fatalf("expected inactive client to block exchange with invalid_grant, got %v", err)
	}
}

func TestInactiveClientBlocksRefresh(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)
	code := mustIssueCode(t, s, client.ClientID, redirect, testVerifier)

	resp, err := s.ExchangeCode(TokenRequest{
		Code:         code,
		ClientID:     client.ClientID,
		RedirectURI:  redirect,
		CodeVerifier: testVerifier,
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	// Deactivate the client, then try to refresh.
	ts := s.store.(*testStore)
	ts.mu.Lock()
	c := ts.clients[client.ClientID]
	c.IsActive = false
	ts.clients[client.ClientID] = c
	ts.mu.Unlock()

	_, err = s.RefreshToken(TokenRequest{
		RefreshToken: resp.RefreshToken,
		ClientID:     client.ClientID,
	})
	oe, ok := err.(*OAuthError)
	if !ok || oe.Code != ErrInvalidGrant {
		t.Fatalf("expected inactive client to block refresh with invalid_grant, got %v", err)
	}
}

func TestInvalidIssuerPanics(t *testing.T) {
	assertPanics := func(name, issuer string) {
		t.Helper()
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("NewAuthorizationServer with issuer %q should panic", issuer)
			}
		}()
		cfg := DefaultConfig()
		cfg.Issuer = issuer
		NewAuthorizationServer(cfg, newTestStore())
	}
	assertPanics("empty", "")
	assertPanics("plain http non-loopback", "http://evil.example.com")
	assertPanics("not a url", "not-a-url")
}
