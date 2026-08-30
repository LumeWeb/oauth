package oauth

// RotateStatus describes the outcome of a refresh-token presentation (RFC 9700
// §4.13 rotation + reuse detection). The Storage adapter performs the atomic
// first-use claim and returns one of these; the AuthorizationServer translates
// it into a token response or a typed error.
type RotateStatus int

const (
	// RotateOK: valid, unexpired, never-used token — rotate and accept.
	RotateOK RotateStatus = iota
	// RotateOKReused: token already rotated but re-presented within the
	// reuse-detection window (benign race: the client had not yet persisted
	// the successor). Accept the same successor without minting a fresh one.
	RotateOKReused
	// RotateReplay: token re-presented beyond the window, or revoked/expired.
	// The whole chain is revoked and the use must be rejected.
	RotateReplay
	// RotateUnknown: no refresh token with this value.
	RotateUnknown
)

// RFC 6749 §5.2 token endpoint error codes.
const (
	ErrInvalidGrant     = "invalid_grant"
	ErrInvalidRequest   = "invalid_request"
	ErrUnsupportedGrant = "unsupported_grant_type"
	ErrInvalidClient    = "invalid_client"
)
