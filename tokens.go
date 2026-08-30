package oauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// NewToken returns a fresh random opaque token string (crypto/rand,
// hex-encoded). nbytes controls the raw byte length: 16 for client IDs, 24
// for authorization codes, 32 for access and refresh tokens.
func NewToken(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("oauth: crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// NewTokenPair issues a (access, refresh) pair of opaque tokens.
func NewTokenPair() (access, refresh string) {
	return NewToken(32), NewToken(32)
}
