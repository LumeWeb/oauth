package oauth

import (
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config holds tunable parameters for the authorization server.
type Config struct {
	// Issuer is the REQUIRED HTTPS issuer URL of this AS (RFC 8414). It is
	// used to validate RFC 8707 resource binding and to derive metadata
	// endpoints.
	Issuer string
	// TokenTTL is the lifetime of issued access tokens. Default: 24h.
	TokenTTL time.Duration
	// RefreshTTL is the lifetime of issued refresh tokens. Default: 720h (30d).
	RefreshTTL time.Duration
	// CodeTTL is the lifetime of authorization codes. Default: 10m.
	CodeTTL time.Duration
	// ClockSkew is the grace period for expired access tokens. Default: 2m.
	ClockSkew time.Duration
	// ReuseWindow is the grace period for re-presented rotated refresh tokens
	// (treated as a benign race, not a replay). Default: 30s.
	ReuseWindow time.Duration
	// ValidateResource, if non-nil, is called to verify that a resource
	// parameter (RFC 8707) identifies an audience this AS is authorized to
	// issue tokens for. When nil, only the issuer URL and resources registered
	// via RegisterResource are accepted.
	ValidateResource func(resource string) bool
}

// DefaultConfig returns a Config with production-safe defaults. Issuer is left
// empty; callers must set it.
func DefaultConfig() Config {
	return Config{
		TokenTTL:    24 * time.Hour,
		RefreshTTL:  720 * time.Hour,
		CodeTTL:     10 * time.Minute,
		ClockSkew:   2 * time.Minute,
		ReuseWindow: 30 * time.Second,
	}
}

// withDefaults fills zero-valued durations in cfg with production-safe
// defaults, mirroring DefaultConfig without disturbing an explicitly set
// Issuer.
func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.TokenTTL <= 0 {
		c.TokenTTL = d.TokenTTL
	}
	if c.RefreshTTL <= 0 {
		c.RefreshTTL = d.RefreshTTL
	}
	if c.CodeTTL <= 0 {
		c.CodeTTL = d.CodeTTL
	}
	if c.ClockSkew <= 0 {
		c.ClockSkew = d.ClockSkew
	}
	if c.ReuseWindow <= 0 {
		c.ReuseWindow = d.ReuseWindow
	}
	return c
}

// ClientRegistration holds DCR request parameters (RFC 7591 §3.1).
type ClientRegistration struct {
	ClientName        string
	RedirectURIs      []string
	GrantTypes        []string
	ResponseTypes     []string
	TokenEndpointAuth string
	Scopes            []string
}

// Client is the server's view of a registered OAuth client.
type Client struct {
	ClientID          string
	ClientName        string
	RedirectURIs      []string
	GrantTypes        []string
	ResponseTypes     []string
	TokenEndpointAuth string
	Scopes            []string
	UserID            *uint
	IsActive          bool
}

// AuthorizeRequest is the parsed authorization request (RFC 6749 §4.1.1).
type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
	Scope               string
}

// TokenRequest is the parsed token endpoint request.
type TokenRequest struct {
	GrantType    string
	Code         string
	ClientID     string
	RedirectURI  string
	CodeVerifier string
	Resource     string
	RefreshToken string
}

// TokenResponse is the standard OAuth token response (RFC 6749 §5.1).
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// AuthorizationCode is a short-lived, single-use code (RFC 6749 §4.1.2).
type AuthorizationCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
	UserID              uint
	Scope               string
	ExpiresAt           time.Time
	UsedAt              *time.Time
}

// RefreshToken represents a refresh token with rotation state (RFC 9700).
type RefreshToken struct {
	Token     string
	ClientID  string
	Resource  string
	UserID    uint
	Scope     string
	ChainRoot string
	ExpiresAt time.Time
	UsedAt    *time.Time
	Revoked   bool
	Successor string
}

// AccessToken represents a persisted access token.
type AccessToken struct {
	Token     string
	ClientID  string
	Resource  string
	UserID    uint
	Scope     string
	ExpiresAt time.Time
}

// ValidatedToken is the outcome of validating a bearer token. It surfaces the
// full grant record so resource servers can enforce RFC 8707 audience binding
// (Resource) and RFC 6749 scope requirements (Scope) rather than only knowing
// the token is known and unexpired.
type ValidatedToken struct {
	// UserID is the resource owner the grant is bound to.
	UserID uint
	// Expiry is the token expiry (raw, before clock-skew grace).
	Expiry time.Time
	// Resource is the RFC 8707 resource (audience) the token was minted for.
	Resource string
	// ClientID is the OAuth client the token was issued to.
	ClientID string
	// Scope is the space-delimited set of scopes granted on the token.
	Scope string
}

// Resource describes a protected resource (RFC 9728 / RFC 8707) that this AS
// is authorized to issue tokens for. Consumers register resources at startup
// so the AS can validate the resource parameter in authorize requests and
// serve protected-resource metadata.
type Resource struct {
	// ResourceURL is the canonical URI identifying the protected resource
	// (RFC 8707 §2). Tokens issued for this resource carry it as the audience.
	ResourceURL string
	// Scopes are the scope values this resource supports (RFC 9728
	// scopes_supported).
	Scopes []string
	// DisplayName is a human-readable name for the resource (RFC 9728
	// resource_name).
	DisplayName string
}

// AuthorizationServer is the core AS — pure domain logic, no HTTP. It
// delegates all persistence to the Storage interface.
type AuthorizationServer struct {
	cfg   Config
	store Storage

	// issuerMu guards cfg.Issuer against concurrent reads (expectedResource,
	// Config) and writes (SetIssuer) during runtime reconfiguration.
	issuerMu sync.RWMutex

	// resMu guards access to the registered resource registry.
	resMu     sync.RWMutex
	resources map[string]Resource
}

// NewAuthorizationServer creates a new AS with the given config and storage.
// Zero-valued durations in cfg are replaced with production-safe defaults.
// It panics if store is nil or cfg.Issuer is missing or not an https (or
// loopback http) URL, since the Issuer is REQUIRED for correct resource
// binding and metadata derivation.
func NewAuthorizationServer(cfg Config, store Storage) *AuthorizationServer {
	if store == nil {
		panic("oauth: NewAuthorizationServer requires a non-nil Storage")
	}
	cfg = cfg.withDefaults()
	validateIssuer(cfg.Issuer)
	return &AuthorizationServer{cfg: cfg, store: store, resources: make(map[string]Resource)}
}

// validateIssuer enforces the REQUIRED HTTPS issuer contract from RFC 8414.
// Plain-HTTP issuers are accepted only for loopback hosts (local development
// and tests) to avoid the certificate burden in those environments.
func validateIssuer(issuer string) {
	if err := validateIssuerErr(issuer); err != nil {
		panic(err.Error())
	}
}

// validateIssuerErr is the non-panicking form of validateIssuer, used by
// runtime reconfiguration paths.
func validateIssuerErr(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return errInvalidIssuer
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if IsLoopbackRedirectURI(u) {
			return nil
		}
	}
	return errNonLoopbackHTTPIssuer
}

// Config returns the effective configuration (with defaults applied).
func (s *AuthorizationServer) Config() Config {
	s.issuerMu.RLock()
	defer s.issuerMu.RUnlock()
	return s.cfg
}

// SetIssuer updates the AS issuer (RFC 8414) at runtime. It re-derives the
// RFC 8707 resource that authorize requests must bind, so it must be called
// whenever the externally reachable base URL changes after startup (e.g. once
// a tunnel allocates its public URL). Invalid issuers are rejected and the
// existing issuer is left untouched.
func (s *AuthorizationServer) SetIssuer(issuer string) error {
	if err := validateIssuerErr(issuer); err != nil {
		return err
	}
	s.issuerMu.Lock()
	s.cfg.Issuer = issuer
	s.issuerMu.Unlock()
	return nil
}

// expectedResource is the RFC 8707 resource this AS serves. Auth requests that
// bind a different resource are rejected.
func (s *AuthorizationServer) expectedResource() string {
	s.issuerMu.RLock()
	defer s.issuerMu.RUnlock()
	return strings.TrimRight(s.cfg.Issuer, "/")
}

// validateResource checks whether a resource parameter (RFC 8707) is an
// audience this AS is authorized to issue tokens for. The check proceeds in
// order: (1) if ValidateResource is configured, defer to the callback;
// (2) accept the issuer URL; (3) accept any URL registered via
// RegisterResource. If none match, the resource is rejected.
func (s *AuthorizationServer) validateResource(resource string) bool {
	if s.cfg.ValidateResource != nil {
		return s.cfg.ValidateResource(resource)
	}
	normalized := strings.TrimRight(resource, "/")
	if normalized == s.expectedResource() {
		return true
	}
	s.resMu.RLock()
	defer s.resMu.RUnlock()
	_, ok := s.resources[normalized]
	return ok
}

// requireActiveClient rejects unknown or deactivated clients before tokens
// are issued.
func (s *AuthorizationServer) requireActiveClient(clientID string) error {
	if clientID == "" {
		return NewInvalidGrantError("client is inactive or unknown")
	}
	client, err := s.store.GetClient(clientID)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			return NewInvalidGrantError("client is inactive or unknown")
		}
		return err
	}
	if !client.IsActive {
		return NewInvalidGrantError("client is inactive")
	}
	return nil
}

// RegisterClient handles Dynamic Client Registration (RFC 7591 §3.1).
func (s *AuthorizationServer) RegisterClient(reg ClientRegistration) (*Client, error) {
	for _, redirectURI := range reg.RedirectURIs {
		if !AllowedClientRedirect(redirectURI) {
			return nil, NewInvalidClientMetadataError("redirect_uri is not allowed")
		}
	}
	if reg.TokenEndpointAuth != "" && reg.TokenEndpointAuth != "none" {
		return nil, NewInvalidClientMetadataError("unsupported token_endpoint_auth_method")
	}
	if len(reg.GrantTypes) == 0 {
		reg.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(reg.ResponseTypes) == 0 {
		reg.ResponseTypes = []string{"code"}
	}
	if reg.TokenEndpointAuth == "" {
		reg.TokenEndpointAuth = "none"
	}
	client := Client{
		ClientID:          "client_" + NewToken(16),
		ClientName:        reg.ClientName,
		RedirectURIs:      reg.RedirectURIs,
		GrantTypes:        reg.GrantTypes,
		ResponseTypes:     reg.ResponseTypes,
		TokenEndpointAuth: reg.TokenEndpointAuth,
		Scopes:            reg.Scopes,
		IsActive:          true,
	}
	if err := s.store.SaveClient(client); err != nil {
		return nil, err
	}
	return &client, nil
}

// ValidateAuthorizeRequest validates a parsed authorization request per
// RFC 6749 §4.1.1 + RFC 7636 §4.3 + RFC 8707. Checks response_type=code,
// client exists, redirect_uri matches, PKCE S256 present and valid, and any
// bound resource matches the expected issuer.
func (s *AuthorizationServer) ValidateAuthorizeRequest(req AuthorizeRequest) error {
	if req.ResponseType != "code" {
		return NewInvalidRequestError("response_type must be code")
	}
	if req.ClientID == "" || req.RedirectURI == "" {
		return NewInvalidRequestError("missing client_id or redirect_uri")
	}
	client, err := s.store.GetClient(req.ClientID)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			return NewInvalidRequestError("unregistered client or redirect_uri")
		}
		return err
	}
	if !MatchRedirectURI(client.RedirectURIs, req.RedirectURI) {
		return NewInvalidRequestError("unregistered client or redirect_uri")
	}
	if !client.IsActive {
		return NewInvalidRequestError("client is inactive")
	}
	if req.CodeChallengeMethod != "S256" || req.CodeChallenge == "" {
		return NewInvalidRequestError("S256 PKCE is required")
	}
	if !ValidBase64URL(req.CodeChallenge) {
		return NewInvalidRequestError("code_challenge must be base64url (RFC 7636)")
	}
	if req.Resource != "" && !s.validateResource(req.Resource) {
		return NewInvalidRequestError("invalid resource")
	}
	return nil
}

// IssueAuthorizationCode creates a short-lived (cfg.CodeTTL), single-use
// authorization code bound to client_id, redirect_uri, code_challenge,
// code_challenge_method, resource, and user_id.
func (s *AuthorizationServer) IssueAuthorizationCode(req AuthorizeRequest, userID uint) (string, error) {
	if err := s.ValidateAuthorizeRequest(req); err != nil {
		return "", err
	}
	code := NewToken(24)
	entry := AuthorizationCode{
		Code:                code,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Resource:            req.Resource,
		UserID:              userID,
		Scope:               req.Scope,
		ExpiresAt:           time.Now().Add(s.cfg.CodeTTL),
	}
	if err := s.store.SaveCode(entry); err != nil {
		return "", err
	}
	return code, nil
}

// ExchangeCode validates PKCE (RFC 7636 §4.6), atomically consumes the
// authorization code, and issues access + refresh tokens (RFC 6749 §5.1).
func (s *AuthorizationServer) ExchangeCode(req TokenRequest) (*TokenResponse, error) {
	entry, err := s.store.GetCode(req.Code)
	if err != nil {
		if errors.Is(err, ErrCodeNotFound) || errors.Is(err, ErrCodeAlreadyUsed) {
			return nil, NewInvalidGrantError("invalid or expired authorization code")
		}
		return nil, err
	}
	if time.Now().After(entry.ExpiresAt) {
		return nil, NewInvalidGrantError("invalid or expired authorization code")
	}
	if req.ClientID != entry.ClientID || req.RedirectURI != entry.RedirectURI ||
		req.Resource != entry.Resource || !VerifyPKCE(req.CodeVerifier, entry.CodeChallenge) {
		return nil, NewInvalidGrantError("invalid client, redirect_uri, code_verifier, or resource")
	}
	// Enforce the client kill-switch before consuming the code.
	if err := s.requireActiveClient(entry.ClientID); err != nil {
		return nil, err
	}
	// Atomic single-use enforcement; only one redemption may win.
	if err := s.store.ConsumeCode(req.Code); err != nil {
		if errors.Is(err, ErrCodeAlreadyUsed) {
			return nil, NewInvalidGrantError("authorization code already used")
		}
		return nil, err
	}
	return s.issueTokenPair(entry.ClientID, entry.Resource, entry.Scope, entry.UserID)
}

// issueTokenPair mints a fresh (access, refresh) pair, persists both, and
// returns the RFC 6749 §5.1 response. The granted scope from the authorization
// is bound to both tokens so a resource server can enforce scope requirements
// against the validated access token.
func (s *AuthorizationServer) issueTokenPair(clientID, resource, scope string, userID uint) (*TokenResponse, error) {
	access, refresh := NewTokenPair()
	accessTok := AccessToken{
		Token:     access,
		ClientID:  clientID,
		Resource:  resource,
		UserID:    userID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(s.cfg.TokenTTL),
	}
	if err := s.store.SaveAccessToken(accessTok); err != nil {
		return nil, err
	}
	if err := s.store.IssueRefreshToken(refresh, clientID, resource, scope, userID); err != nil {
		return nil, err
	}
	return &TokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.cfg.TokenTTL.Seconds()),
		RefreshToken: refresh,
	}, nil
}

// resolveRefreshClient returns the effective clientID for a refresh. An empty
// client_id is resolved from the token so the active-client check still applies.
// Returns (clientID, err).
func (s *AuthorizationServer) refreshClient(req TokenRequest) (string, error) {
	if req.ClientID != "" {
		return req.ClientID, nil
	}
	rt, err := s.store.GetRefreshToken(req.RefreshToken)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenNotFound) {
			return "", NewInvalidGrantError("the refresh token is invalid, expired, or unknown")
		}
		return "", err
	}
	return rt.ClientID, nil
}

func (s *AuthorizationServer) RefreshToken(req TokenRequest) (*TokenResponse, error) {
	clientID, err := s.refreshClient(req)
	if err != nil {
		return nil, err
	}
	if err := s.requireActiveClient(clientID); err != nil {
		return nil, err
	}
	_, userID, boundResource, boundScope, successor, status, err := s.store.RotateRefreshToken(req.RefreshToken, clientID, req.Resource)
	if err != nil {
		return nil, err
	}
	switch status {
	case RotateOK, RotateOKReused:
		// Successor already persisted by RotateRefreshToken; store the fresh access token.
		// The refreshed token keeps the grant's bound scope (RFC 6749 §6) so
		// downstream scope enforcement stays consistent across rotation.
		access := NewToken(32)
		expiry := time.Now().Add(s.cfg.TokenTTL)
		if err := s.store.SaveAccessToken(AccessToken{
			Token:     access,
			ClientID:  clientID,
			Resource:  boundResource,
			UserID:    userID,
			Scope:     boundScope,
			ExpiresAt: expiry,
		}); err != nil {
			return nil, err
		}
		return &TokenResponse{
			AccessToken:  access,
			TokenType:    "Bearer",
			ExpiresIn:    int(s.cfg.TokenTTL.Seconds()),
			RefreshToken: successor,
		}, nil
	case RotateReplay:
		return nil, NewInvalidGrantError("the refresh token has been replayed and the grant has been revoked")
	default:
		return nil, NewInvalidGrantError("the refresh token is invalid, expired, or unknown")
	}
}

// ValidateAccessToken checks whether a bearer token is valid (not expired
// within the clock-skew grace). Returns the bound userID and expiry if valid.
// Use ValidateAccessTokenInfo when the caller also needs the token's bound
// resource (RFC 8707 audience) and scope for resource-server enforcement.
func (s *AuthorizationServer) ValidateAccessToken(token string) (userID uint, expiry time.Time, ok bool) {
	vt, ok := s.ValidateAccessTokenInfo(token)
	return vt.UserID, vt.Expiry, ok
}

// ValidateAccessTokenInfo checks whether a bearer token is valid (not expired
// within the clock-skew grace) and returns the full validated record. The
// ValidatedToken exposes the RFC 8707 bound resource and the granted scope so
// a resource server (e.g. an MCP server) can enforce audience binding and
// scope requirements, not merely token liveness.
func (s *AuthorizationServer) ValidateAccessTokenInfo(token string) (ValidatedToken, bool) {
	at, err := s.store.GetAccessToken(token)
	if err != nil {
		return ValidatedToken{}, false
	}
	now := time.Now()
	if now.After(at.ExpiresAt.Add(s.cfg.ClockSkew)) {
		// Beyond the skew boundary: purge so a restart never resurrects it.
		_ = s.store.DeleteAccessToken(token)
		return ValidatedToken{}, false
	}
	return ValidatedToken{
		UserID:   at.UserID,
		Expiry:   at.ExpiresAt,
		Resource: at.Resource,
		ClientID: at.ClientID,
		Scope:    at.Scope,
	}, true
}

// RevokeToken revokes an access token or an entire refresh-token chain
// (RFC 7009). Revocation is idempotent: presenting an unknown or
// already-revoked token is not an error.
func (s *AuthorizationServer) RevokeToken(token string) error {
	rt, err := s.store.GetRefreshToken(token)
	if err == nil {
		// It is a refresh token: revoke its whole chain.
		return s.store.RevokeChain(rt.ChainRoot)
	}
	if !errors.Is(err, ErrRefreshTokenNotFound) {
		return err
	}
	// Not a refresh token: treat it as an access token.
	if err := s.store.DeleteAccessToken(token); err != nil && !errors.Is(err, ErrTokenNotFound) {
		return err
	}
	return nil
}

// Reap deletes expired codes, tokens, and stale clients.
func (s *AuthorizationServer) Reap() error {
	return s.store.Reap(time.Now())
}

// ---- Resource registry (RFC 8707 / RFC 9728) ----

// RegisterResource registers a protected resource that this AS is authorized
// to issue tokens for. Duplicate registrations for the same ResourceURL update
// the existing entry. Registrations are in-memory; callers should re-register
// on restart.
func (s *AuthorizationServer) RegisterResource(reg Resource) {
	normalized := strings.TrimRight(reg.ResourceURL, "/")
	reg.ResourceURL = normalized
	s.resMu.Lock()
	defer s.resMu.Unlock()
	s.resources[normalized] = reg
}

// UnregisterResource removes a previously registered resource. If the resource
// is not registered, this is a no-op.
func (s *AuthorizationServer) UnregisterResource(resourceURL string) {
	normalized := strings.TrimRight(resourceURL, "/")
	s.resMu.Lock()
	defer s.resMu.Unlock()
	delete(s.resources, normalized)
}

// GetResource returns the registration for a resource URL and a boolean
// indicating whether it was found.
func (s *AuthorizationServer) GetResource(resourceURL string) (Resource, bool) {
	normalized := strings.TrimRight(resourceURL, "/")
	s.resMu.RLock()
	defer s.resMu.RUnlock()
	reg, ok := s.resources[normalized]
	return reg, ok
}

// ListResources returns all registered resources.
func (s *AuthorizationServer) ListResources() []Resource {
	s.resMu.RLock()
	defer s.resMu.RUnlock()
	list := make([]Resource, 0, len(s.resources))
	for _, r := range s.resources {
		list = append(list, r)
	}
	return list
}
