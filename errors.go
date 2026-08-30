package oauth

import (
	"errors"
	"fmt"
)

// OAuthError wraps an RFC 6749 §5.2 error code with a human-readable
// description. Token endpoint handlers map its Code directly onto the "error"
// response field.
type OAuthError struct {
	Code        string // e.g. "invalid_grant", "invalid_request"
	Description string
}

// Error implements the error interface as "<code>: <description>".
func (e *OAuthError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// NewInvalidGrantError returns an error with code "invalid_grant".
func NewInvalidGrantError(desc string) *OAuthError {
	return &OAuthError{Code: ErrInvalidGrant, Description: desc}
}

// NewInvalidRequestError returns an error with code "invalid_request".
func NewInvalidRequestError(desc string) *OAuthError {
	return &OAuthError{Code: ErrInvalidRequest, Description: desc}
}

// NewUnsupportedGrantTypeError returns an error with code
// "unsupported_grant_type".
func NewUnsupportedGrantTypeError(desc string) *OAuthError {
	return &OAuthError{Code: ErrUnsupportedGrant, Description: desc}
}

// NewInvalidClientMetadataError returns an error signalling malformed dynamic
// client registration metadata (RFC 7591 §3.2.2).
func NewInvalidClientMetadataError(desc string) *OAuthError {
	return &OAuthError{Code: "invalid_client_metadata", Description: desc}
}

// Issuer validation errors returned by SetIssuer.
var (
	// errInvalidIssuer indicates the issuer is not a valid URL with a host.
	errInvalidIssuer = errors.New("oauth: Config.Issuer is required and must be a valid URL")
	// errNonLoopbackHTTPIssuer indicates an http (non-https) issuer that is
	// not on a loopback host, which is disallowed by the RFC 8414 contract.
	errNonLoopbackHTTPIssuer = errors.New("oauth: Config.Issuer must use https (or http on a loopback host)")
)

// Sentinel storage errors. Storage implementations return these so the
// AuthorizationServer can translate persistence outcomes into RFC 6749 §5.2
// responses without depending on any concrete storage library.
var (
	// ErrClientNotFound is returned when a client ID is not registered.
	ErrClientNotFound = &OAuthError{Code: "client_not_found", Description: "no such registered client"}
	// ErrCodeNotFound is returned when an authorization code is unknown or
	// has already been redeemed.
	ErrCodeNotFound = &OAuthError{Code: "code_not_found", Description: "authorization code is invalid or already used"}
	// ErrCodeAlreadyUsed is returned when a single-use code is presented a
	// second time.
	ErrCodeAlreadyUsed = &OAuthError{Code: "code_already_used", Description: "authorization code has already been used"}
	// ErrTokenNotFound is returned when an access token is unknown.
	ErrTokenNotFound = &OAuthError{Code: "token_not_found", Description: "access token is invalid or unknown"}
	// ErrRefreshTokenNotFound is returned when a refresh token is unknown.
	ErrRefreshTokenNotFound = &OAuthError{Code: "refresh_token_not_found", Description: "refresh token is invalid or unknown"}
)
