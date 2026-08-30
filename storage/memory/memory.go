// Package memory provides an in-memory oauth.Storage implementation useful for
// tests, development, and single-instance deployments that do not need
// persistence across restarts. It uses mutex-guarded maps rather than a
// database and so implements the same RFC 9700 rotation + reuse-detection
// invariants with lock-based atomicity.
package memory

import (
	"sync"
	"time"

	"go.lumeweb.com/oauth"
)

// Ensure Storage satisfies oauth.Storage at compile time.
var _ oauth.Storage = (*Storage)(nil)

// Storage implements oauth.Storage using synchronized in-memory maps. It is
// not durable across process restarts.
type Storage struct {
	mu            sync.Mutex
	clients       map[string]oauth.Client
	codes         map[string]oauth.AuthorizationCode
	refreshTokens map[string]oauth.RefreshToken
	accessTokens  map[string]oauth.AccessToken
	clientCreated map[string]time.Time
	refreshTTL    time.Duration
	reuseWindow   time.Duration
}

// New creates an in-memory oauth.Storage. The zero-valued refresh/reuse
// durations fall back to production-safe defaults.
func New(cfg oauth.Config) *Storage {
	refreshTTL := cfg.RefreshTTL
	if refreshTTL <= 0 {
		refreshTTL = 720 * time.Hour
	}
	reuseWindow := cfg.ReuseWindow
	if reuseWindow <= 0 {
		reuseWindow = 30 * time.Second
	}
	return &Storage{
		clients:       make(map[string]oauth.Client),
		codes:         make(map[string]oauth.AuthorizationCode),
		refreshTokens: make(map[string]oauth.RefreshToken),
		accessTokens:  make(map[string]oauth.AccessToken),
		clientCreated: make(map[string]time.Time),
		refreshTTL:    refreshTTL,
		reuseWindow:   reuseWindow,
	}
}

// Close is a no-op for the in-memory storage.
func (s *Storage) Close() error { return nil }

// ---- clients ----

// SaveClient persists a registered client and records its registration time
// for age-based reaping.
func (s *Storage) SaveClient(c oauth.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Preserve the original registration time on re-save, mirroring the GORM
	// adapter's upsert-keeps-CreatedAt behavior so reaping stays consistent.
	if _, ok := s.clientCreated[c.ClientID]; !ok {
		s.clientCreated[c.ClientID] = time.Now()
	}
	s.clients[c.ClientID] = c
	return nil
}

// GetClient retrieves a client by ID, returning oauth.ErrClientNotFound if
// absent.
func (s *Storage) GetClient(clientID string) (oauth.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		return oauth.Client{}, oauth.ErrClientNotFound
	}
	return c, nil
}

// AllClients returns every registered client.
func (s *Storage) AllClients() ([]oauth.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]oauth.Client, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, c)
	}
	return out, nil
}

// ---- authorization codes ----

// SaveCode stores a new authorization code.
func (s *Storage) SaveCode(code oauth.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.Code] = code
	return nil
}

// GetCode retrieves a code by value, returning oauth.ErrCodeNotFound if absent
// or already used.
func (s *Storage) GetCode(code string) (oauth.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	if !ok || c.UsedAt != nil {
		return oauth.AuthorizationCode{}, oauth.ErrCodeNotFound
	}
	return c, nil
}

// ConsumeCode atomically marks a code as used, enforcing single-use. Returns
// oauth.ErrCodeAlreadyUsed if already consumed.
func (s *Storage) ConsumeCode(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	if !ok {
		return oauth.ErrCodeNotFound
	}
	if c.UsedAt != nil {
		return oauth.ErrCodeAlreadyUsed
	}
	now := time.Now()
	c.UsedAt = &now
	s.codes[code] = c
	return nil
}

// ---- refresh tokens ----

// IssueRefreshToken stores the initial refresh token of a new chain (the
// root). The root has no successor yet.
func (s *Storage) IssueRefreshToken(token, clientID, resource string, userID uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issueInChainLocked(token, "", clientID, resource, token, userID)
}

// GetRefreshToken retrieves a refresh token by value, returning
// oauth.ErrRefreshTokenNotFound if absent.
func (s *Storage) GetRefreshToken(token string) (oauth.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refreshTokens[token]
	if !ok {
		return oauth.RefreshToken{}, oauth.ErrRefreshTokenNotFound
	}
	return rt, nil
}

// issueInChainLocked stores a refresh token whose chain root is chainRoot.
// Callers must hold s.mu.
func (s *Storage) issueInChainLocked(token, successor, clientID, resource, chainRoot string, userID uint) error {
	s.refreshTokens[token] = oauth.RefreshToken{
		Token:     token,
		ClientID:  clientID,
		Resource:  resource,
		UserID:    userID,
		ChainRoot: chainRoot,
		ExpiresAt: time.Now().Add(s.refreshTTL),
		Successor: successor,
	}
	return nil
}

// RotateRefreshToken implements RFC 9700 §4.13 rotation + reuse detection.
// The whole decision runs under a single mutex; lock-held helpers are used
// for chain revocation and successor issuance.
func (s *Storage) RotateRefreshToken(token, clientID, resource string) (string, uint, string, oauth.RotateStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rt, ok := s.refreshTokens[token]
	if !ok {
		return "", 0, "", oauth.RotateUnknown, nil
	}
	now := time.Now()
	if rt.Revoked || now.After(rt.ExpiresAt) {
		return "", 0, "", oauth.RotateReplay, nil
	}
	if clientID != "" && rt.ClientID != clientID {
		return "", 0, "", oauth.RotateReplay, nil
	}
	if resource != "" && rt.Resource != "" && resource != rt.Resource {
		return "", 0, "", oauth.RotateReplay, nil
	}
	if rt.UsedAt != nil {
		return s.resolvePostUseLocked(rt, now)
	}
	succ := oauth.NewToken(32)
	usedAt := now
	rt.UsedAt = &usedAt
	rt.Successor = succ
	s.refreshTokens[token] = rt
	if err := s.issueInChainLocked(succ, "", rt.ClientID, rt.Resource, rt.ChainRoot, rt.UserID); err != nil {
		return "", 0, "", oauth.RotateUnknown, err
	}
	return rt.ClientID, rt.UserID, succ, oauth.RotateOK, nil
}

// resolvePostUseLocked applies reuse-vs-replay to an already-rotated token.
// In-window reuse returns the same successor (no fresh mint); beyond the
// window the chain is revoked. Caller must hold s.mu.
func (s *Storage) resolvePostUseLocked(rt oauth.RefreshToken, now time.Time) (string, uint, string, oauth.RotateStatus, error) {
	if rt.UsedAt == nil {
		return "", 0, "", oauth.RotateReplay, nil
	}
	if now.Sub(*rt.UsedAt) <= s.reuseWindow {
		if rt.Successor == "" {
			return "", 0, "", oauth.RotateReplay, nil
		}
		return rt.ClientID, rt.UserID, rt.Successor, oauth.RotateOKReused, nil
	}
	if err := s.revokeChainLocked(rt.ChainRoot); err != nil {
		return "", 0, "", oauth.RotateUnknown, err
	}
	return "", 0, "", oauth.RotateReplay, nil
}

// RevokeChain marks every token in a chain as revoked (RFC 7009).
func (s *Storage) RevokeChain(chainRoot string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokeChainLocked(chainRoot)
}

// revokeChainLocked marks every token in a chain as revoked. The caller must
// hold s.mu (sync.Mutex is not reentrant, so replay handling that already
// holds the lock must route through this rather than RevokeChain).
func (s *Storage) revokeChainLocked(chainRoot string) error {
	for token, rt := range s.refreshTokens {
		if rt.ChainRoot == chainRoot {
			rt.Revoked = true
			s.refreshTokens[token] = rt
		}
	}
	return nil
}

// ---- access tokens ----

// SaveAccessToken persists an access token.
func (s *Storage) SaveAccessToken(token oauth.AccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTokens[token.Token] = token
	return nil
}

// GetAccessToken retrieves an access token by value, returning
// oauth.ErrTokenNotFound if absent.
func (s *Storage) GetAccessToken(token string) (oauth.AccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.accessTokens[token]
	if !ok {
		return oauth.AccessToken{}, oauth.ErrTokenNotFound
	}
	return at, nil
}

// DeleteAccessToken removes a single access token. It is idempotent.
func (s *Storage) DeleteAccessToken(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.accessTokens, token)
	return nil
}

// AllAccessTokens returns every persisted access token.
func (s *Storage) AllAccessTokens() ([]oauth.AccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]oauth.AccessToken, 0, len(s.accessTokens))
	for _, at := range s.accessTokens {
		out = append(out, at)
	}
	return out, nil
}

// ---- lifecycle ----

// Reap removes expired codes, tokens, and stale clients.
func (s *Storage) Reap(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for code, c := range s.codes {
		if now.After(c.ExpiresAt) {
			delete(s.codes, code)
		}
	}
	for token, rt := range s.refreshTokens {
		if now.After(rt.ExpiresAt) {
			delete(s.refreshTokens, token)
		}
	}
	for token, at := range s.accessTokens {
		if now.After(at.ExpiresAt) {
			delete(s.accessTokens, token)
		}
	}
	// Stale clients: age-based retention, matching the GORM adapter (expired
	// beyond refreshTTL are removed).
	for id, created := range s.clientCreated {
		if now.After(created.Add(s.refreshTTL)) {
			delete(s.clients, id)
			delete(s.clientCreated, id)
		}
	}
	return nil
}
