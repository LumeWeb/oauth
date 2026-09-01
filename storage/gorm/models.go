package gorm

import (
	"time"

	"gorm.io/gorm"
)

// OAuthClient is a registered OAuth client (RFC 7591). Exported so consumers
// can reference the GORM tags when writing their own migration SQL.
type OAuthClient struct {
	gorm.Model
	ClientID          string `gorm:"uniqueIndex;not null;column:client_id"`
	ClientURI         string `gorm:"type:text;column:client_uri"`
	ClientName        string `gorm:"column:client_name"`
	RedirectURIs      string `gorm:"type:text;column:redirect_uris"`
	GrantTypes        string `gorm:"type:text;column:grant_types"`
	ResponseTypes     string `gorm:"type:text;column:response_types"`
	TokenEndpointAuth string `gorm:"column:token_endpoint_auth_method"`
	Scopes            string `gorm:"type:text;column:scopes"`
	UserID            *uint  `gorm:"index;column:user_id"`
	IsActive          bool   `gorm:"default:true;column:is_active"`
}

// TableName returns the oauth_clients table name.
func (OAuthClient) TableName() string { return "oauth_clients" }

// OAuthAuthorizationCode is a short-lived, single-use authorization code.
type OAuthAuthorizationCode struct {
	gorm.Model
	Code                string     `gorm:"uniqueIndex;not null;column:code"`
	ClientID            string     `gorm:"index;not null;column:client_id"`
	RedirectURI         string     `gorm:"column:redirect_uri"`
	CodeChallenge       string     `gorm:"column:code_challenge"`
	CodeChallengeMethod string     `gorm:"column:code_challenge_method"`
	Resource            string     `gorm:"column:resource"`
	UserID              uint       `gorm:"not null;column:user_id"`
	Scope               string     `gorm:"column:scope"`
	ExpiresAt           time.Time  `gorm:"not null;column:expires_at"`
	UsedAt              *time.Time `gorm:"column:used_at"`
}

// TableName returns the oauth_authorization_codes table name.
func (OAuthAuthorizationCode) TableName() string { return "oauth_authorization_codes" }

// OAuthRefreshToken implements RFC 9700 rotation + reuse detection.
type OAuthRefreshToken struct {
	gorm.Model
	Token     string     `gorm:"uniqueIndex;not null;column:token"`
	ClientID  string     `gorm:"index;not null;column:client_id"`
	Resource  string     `gorm:"column:resource"`
	UserID    uint       `gorm:"not null;column:user_id"`
	Scope     string     `gorm:"column:scope"`
	ChainRoot string     `gorm:"index;column:chain_root"`
	ExpiresAt time.Time  `gorm:"not null;column:expires_at"`
	UsedAt    *time.Time `gorm:"column:used_at"`
	Revoked   bool       `gorm:"default:false;column:revoked"`
	Successor string     `gorm:"column:successor"`
}

// TableName returns the oauth_refresh_tokens table name.
func (OAuthRefreshToken) TableName() string { return "oauth_refresh_tokens" }

// OAuthAccessToken is a persisted access token for restart resilience.
type OAuthAccessToken struct {
	gorm.Model
	Token     string    `gorm:"uniqueIndex;not null;column:token"`
	ClientID  string    `gorm:"index;not null;column:client_id"`
	Resource  string    `gorm:"column:resource"`
	UserID    uint      `gorm:"not null;column:user_id"`
	Scope     string    `gorm:"column:scope"`
	ExpiresAt time.Time `gorm:"not null;column:expires_at"`
}

// TableName returns the oauth_access_tokens table name.
func (OAuthAccessToken) TableName() string { return "oauth_access_tokens" }
