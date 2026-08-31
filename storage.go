package oauth

import "time"

// Storage is the persistence abstraction for OAuth state. The AuthorizationServer
// delegates all reads and writes to it, keeping the domain logic free of any
// concrete storage library.
//
// Implementations:
//   - go.lumeweb.com/oauth/storage/gorm  (GORM; portal + pinner-cli)
//   - go.lumeweb.com/oauth/storage/memory (in-memory; tests / dev)
//   - Future: Redis, etc.
type Storage interface {
	// ---- Clients (RFC 7591) ----

	// SaveClient persists a registered client.
	SaveClient(client Client) error

	// GetClient retrieves a client by ID. Returns ErrClientNotFound if not
	// found.
	GetClient(clientID string) (Client, error)

	// AllClients returns all registered clients (for restart repopulation).
	AllClients() ([]Client, error)

	// ---- Authorization codes (RFC 6749 §4.1.2) ----

	// SaveCode stores a new authorization code.
	SaveCode(code AuthorizationCode) error

	// GetCode retrieves a code by value. Returns ErrCodeNotFound if not found
	// or already used.
	GetCode(code string) (AuthorizationCode, error)

	// ConsumeCode atomically marks a code as used (single-use enforcement).
	// Returns ErrCodeAlreadyUsed if already consumed.
	ConsumeCode(code string) error

	// ---- Refresh tokens (RFC 9700) ----

	// IssueRefreshToken stores the initial refresh token of a new chain.
	IssueRefreshToken(token, clientID, resource, scope string, userID uint) error

	// GetRefreshToken retrieves a refresh token by value. Returns
	// ErrRefreshTokenNotFound if not found.
	GetRefreshToken(token string) (RefreshToken, error)

	// RotateRefreshToken performs RFC 9700 §4.13 rotation + reuse detection.
	// Returns (clientID, userID, boundResource, scope, successor, status,
	// error). userID is the resource-owner bound to the grant; boundResource
	// and scope are the RFC 8707 resource and granted scope carried through
	// rotation so a refreshed access token keeps the holder's identity,
	// audience, and scope.
	RotateRefreshToken(token, clientID, resource string) (string, uint, string, string, string, RotateStatus, error)

	// RevokeChain revokes every token in a chain (RFC 7009).
	RevokeChain(chainRoot string) error

	// ---- Access tokens ----

	// SaveAccessToken persists an access token.
	SaveAccessToken(token AccessToken) error

	// GetAccessToken retrieves an access token by value. Returns
	// ErrTokenNotFound if not found.
	GetAccessToken(token string) (AccessToken, error)

	// DeleteAccessToken removes an access token (delete-on-eviction).
	DeleteAccessToken(token string) error

	// AllAccessTokens returns all access tokens (for restart repopulation).
	AllAccessTokens() ([]AccessToken, error)

	// ---- Lifecycle ----

	// Reap deletes expired codes, tokens, and stale clients.
	Reap(now time.Time) error

	// Close releases storage resources.
	Close() error
}
