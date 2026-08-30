package oauth

import (
	"sync"
	"time"
)

// testStore is a self-contained in-memory oauth.Storage defined inside the
// package tests. It exists to exercise the AuthorizationServer facade without
// importing an adapter (which would create a test-only import cycle). It is
// deliberately simple and not the production memory adapter.
type testStore struct {
	mu            sync.Mutex
	clients       map[string]Client
	codes         map[string]AuthorizationCode
	refreshTokens map[string]RefreshToken
	accessTokens  map[string]AccessToken
	refreshTTL    time.Duration
	reuseWindow   time.Duration
}

func newTestStore() *testStore {
	return &testStore{
		clients:       map[string]Client{},
		codes:         map[string]AuthorizationCode{},
		refreshTokens: map[string]RefreshToken{},
		accessTokens:  map[string]AccessToken{},
		refreshTTL:    30 * 24 * time.Hour,
		reuseWindow:   30 * time.Second,
	}
}

func (ts *testStore) SaveClient(c Client) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.clients[c.ClientID] = c
	return nil
}

func (ts *testStore) GetClient(clientID string) (Client, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	c, ok := ts.clients[clientID]
	if !ok {
		return Client{}, ErrClientNotFound
	}
	return c, nil
}

func (ts *testStore) AllClients() ([]Client, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	out := make([]Client, 0, len(ts.clients))
	for _, c := range ts.clients {
		out = append(out, c)
	}
	return out, nil
}

func (ts *testStore) SaveCode(code AuthorizationCode) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.codes[code.Code] = code
	return nil
}

func (ts *testStore) GetCode(code string) (AuthorizationCode, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	c, ok := ts.codes[code]
	if !ok || c.UsedAt != nil {
		return AuthorizationCode{}, ErrCodeNotFound
	}
	return c, nil
}

func (ts *testStore) ConsumeCode(code string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	c, ok := ts.codes[code]
	if !ok {
		return ErrCodeNotFound
	}
	if c.UsedAt != nil {
		return ErrCodeAlreadyUsed
	}
	now := time.Now()
	c.UsedAt = &now
	ts.codes[code] = c
	return nil
}

func (ts *testStore) IssueRefreshToken(token, clientID, resource string, userID uint) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.refreshTokens[token] = RefreshToken{
		Token:     token,
		ClientID:  clientID,
		Resource:  resource,
		UserID:    userID,
		ChainRoot: token,
		ExpiresAt: time.Now().Add(ts.refreshTTL),
	}
	return nil
}

func (ts *testStore) GetRefreshToken(token string) (RefreshToken, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	rt, ok := ts.refreshTokens[token]
	if !ok {
		return RefreshToken{}, ErrRefreshTokenNotFound
	}
	return rt, nil
}

func (ts *testStore) RotateRefreshToken(token, clientID, resource string) (string, uint, string, RotateStatus, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	rt, ok := ts.refreshTokens[token]
	if !ok {
		return "", 0, "", RotateUnknown, nil
	}
	now := time.Now()
	if rt.Revoked || now.After(rt.ExpiresAt) {
		return "", 0, "", RotateReplay, nil
	}
	if clientID != "" && rt.ClientID != clientID {
		return "", 0, "", RotateReplay, nil
	}
	if resource != "" && rt.Resource != "" && resource != rt.Resource {
		return "", 0, "", RotateReplay, nil
	}
	if rt.UsedAt != nil {
		if now.Sub(*rt.UsedAt) <= ts.reuseWindow && rt.Successor != "" {
			return rt.ClientID, rt.UserID, rt.Successor, RotateOKReused, nil
		}
		_ = ts.revokeChainLocked(rt.ChainRoot)
		return "", 0, "", RotateReplay, nil
	}
	succ := NewToken(32)
	usedAt := now
	rt.UsedAt = &usedAt
	rt.Successor = succ
	ts.refreshTokens[token] = rt
	ts.refreshTokens[succ] = RefreshToken{
		Token:     succ,
		ClientID:  rt.ClientID,
		Resource:  rt.Resource,
		UserID:    rt.UserID,
		ChainRoot: rt.ChainRoot,
		ExpiresAt: now.Add(ts.refreshTTL),
	}
	return rt.ClientID, rt.UserID, succ, RotateOK, nil
}

func (ts *testStore) revokeChainLocked(root string) error {
	for token, rt := range ts.refreshTokens {
		if rt.ChainRoot == root {
			rt.Revoked = true
			ts.refreshTokens[token] = rt
		}
	}
	return nil
}

func (ts *testStore) RevokeChain(chainRoot string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.revokeChainLocked(chainRoot)
}

func (ts *testStore) SaveAccessToken(token AccessToken) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.accessTokens[token.Token] = token
	return nil
}

func (ts *testStore) GetAccessToken(token string) (AccessToken, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	at, ok := ts.accessTokens[token]
	if !ok {
		return AccessToken{}, ErrTokenNotFound
	}
	return at, nil
}

func (ts *testStore) DeleteAccessToken(token string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.accessTokens, token)
	return nil
}

func (ts *testStore) AllAccessTokens() ([]AccessToken, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	out := make([]AccessToken, 0, len(ts.accessTokens))
	for _, at := range ts.accessTokens {
		out = append(out, at)
	}
	return out, nil
}

func (ts *testStore) Reap(now time.Time) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for code, c := range ts.codes {
		if now.After(c.ExpiresAt) {
			delete(ts.codes, code)
		}
	}
	for token, rt := range ts.refreshTokens {
		if now.After(rt.ExpiresAt) {
			delete(ts.refreshTokens, token)
		}
	}
	for token, at := range ts.accessTokens {
		if now.After(at.ExpiresAt) {
			delete(ts.accessTokens, token)
		}
	}
	return nil
}

func (ts *testStore) Close() error { return nil }
