package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// VerifyPKCE verifies a PKCE code_verifier against the stored code_challenge
// using the S256 method (RFC 7636 §4.6).
//
//	sha256(code_verifier) → base64.RawURLEncoding → subtle.ConstantTimeCompare
//
// The verifier length is constrained to RFC 7636 §4.1 (43-128 chars) before
// hashing.
func VerifyPKCE(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare(
		[]byte(base64.RawURLEncoding.EncodeToString(sum[:])),
		[]byte(challenge),
	) == 1
}

// ValidBase64URL reports whether s contains only the RFC 4648 base64url
// alphabet plus the RFC 7636 additional allowed characters (-._~). Rejecting
// anything else keeps attacker-controlled raw markup out of authorization
// pages even if a downstream render path were to regress.
func ValidBase64URL(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '_', r == '~':
		default:
			return false
		}
	}
	return true
}
