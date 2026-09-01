package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// CIMDClientMetadata is the subset of a client metadata document (RFC 9291
// §2.2) the AS needs to process a URL-form client_id. It mirrors the fields
// validated during dynamic client registration (RFC 7591 §3.2.1).
type CIMDClientMetadata struct {
	ClientID                string
	ClientName              string
	RedirectURIs            []string
	TokenEndpointAuthMethod string
}

// cimdCacheEntry is a resolved CIMD document with its fetch time, used to
// enforce the TTL so a client that rotates its metadata document is picked up
// without a process restart.
type cimdCacheEntry struct {
	metadata  CIMDClientMetadata
	fetchedAt time.Time
}

// Default CIMD tunables. They match the reference behavior of pinner-cli so
// the two authorization servers share the same SSRF and freshness posture.
const (
	// cimdCacheTTL is how long a fetched CIMD document stays fresh before it
	// is re-fetched on next use.
	cimdCacheTTL = 5 * time.Minute
	// cimdFetchTimeout bounds the outbound GET so a slow or hostile host
	// cannot stall the authorize flow.
	cimdFetchTimeout = 10 * time.Second
	// cimdMaxBodyBytes caps the document size read from the wire.
	cimdMaxBodyBytes = 64 * 1024
)

// defaultCIMDAllowedHosts is the initial allowlist of hosts whose CIMD
// documents a CIMDResolver will fetch. It starts with the known MCP
// authorization-server hosts; consumers extend it with AllowHost.
var defaultCIMDAllowedHosts = map[string]bool{
	"claude.ai":  true,
	"vscode.dev": true,
}

// CIMDResolver resolves URL-form client_ids (RFC 9291) into client metadata
// documents. It is the resolution half of AS-level CIMD support: it fetches
// only hosts on an explicit allowlist (the SSRF defense), validates the
// fetched document, and caches results for a TTL so repeated authorize
// requests from the same client do not re-fetch.
//
// Resolution requires outbound networking, so unlike the rest of this package
// it is not pure domain logic; it is used only by a consumer that opts in via
// AuthorizationServer.WithCIMDResolver.
type CIMDResolver struct {
	allowedHosts map[string]bool
	cache        map[string]cimdCacheEntry
	ttl          time.Duration
	client       *http.Client
	mu           sync.Mutex
}

// NewCIMDResolver returns a resolver seeded with the default host allowlist
// and a fresh empty cache.
func NewCIMDResolver() *CIMDResolver {
	return &CIMDResolver{
		allowedHosts: maps.Clone(defaultCIMDAllowedHosts),
		cache:        make(map[string]cimdCacheEntry),
		ttl:          cimdCacheTTL,
		client: &http.Client{
			Timeout: cimdFetchTimeout,
			// CIMD documents are fetched from the exact URL the client sent.
			// Following redirects could smuggle the fetch to an un-allowlisted
			// host, so any redirect is treated as an error.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// AllowHost adds hosts to the resolver's allowlist. It is used to grant
// fetch permission to hosts beyond the defaults (for example a development
// or test server on loopback). It is safe to call concurrently with Resolve.
func (r *CIMDResolver) AllowHost(hosts ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, h := range hosts {
		if h != "" {
			r.allowedHosts[h] = true
		}
	}
}

// IsClientIDDocumentURL reports whether clientID is a URL-form client
// identifier that should be resolved as a CIMD document (RFC 9291 §3). Per
// the spec the URL must use https and contain a path component; http is
// accepted for loopback hosts so development and test environments can
// exercise the path without provisioning TLS certificates.
func (r *CIMDResolver) IsClientIDDocumentURL(clientID string) bool {
	u, err := url.Parse(clientID)
	if err != nil {
		return false
	}
	if u.Host == "" || u.Path == "" || u.Path == "/" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return true
		}
	}
	return false
}

// allowedHost reports whether the URL's host is permitted to be fetched. The
// allowlist is the sole gate: a host must be in the explicit allowlist (a
// consumer adds known/trusted hosts via AllowHost) or the fetch is rejected.
// No DNS-based filtering is attempted — resolving the host here would differ
// from the resolution the HTTP client performs on the actual request, and
// trusting that result would open a DNS-rebinding TOCTOU hole. Rejecting any
// non-allowlisted host outright is both simpler and the actual SSRF defense.
func (r *CIMDResolver) allowedHost(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	r.mu.Lock()
	allowlisted := r.allowedHosts[host]
	r.mu.Unlock()
	return allowlisted
}

// Resolve fetches and validates the client metadata document at the URL-form
// clientID, returning the parsed metadata. Results are cached for the
// resolver's TTL so repeated calls within the window do not re-fetch.
func (r *CIMDResolver) Resolve(ctx context.Context, clientID string) (CIMDClientMetadata, error) {
	var zero CIMDClientMetadata

	r.mu.Lock()
	if entry, ok := r.cache[clientID]; ok && time.Since(entry.fetchedAt) < r.ttl {
		r.mu.Unlock()
		return entry.metadata, nil
	}
	r.mu.Unlock()

	if !r.allowedHost(clientID) {
		return zero, errors.New("client metadata host is not allowlisted")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return zero, fmt.Errorf("could not build client metadata request: %w", err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return zero, errors.New("could not fetch client metadata document")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("client metadata document returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBodyBytes))
	if err != nil {
		return zero, errors.New("could not read client metadata document")
	}

	var doc struct {
		ClientID                string   `json:"client_id"`
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return zero, errors.New("invalid client metadata document JSON")
	}
	if doc.ClientID != clientID {
		return zero, errors.New("client_id in metadata document does not match the request URL")
	}
	if len(doc.RedirectURIs) == 0 {
		return zero, errors.New("client metadata document has no redirect_uris")
	}
	if doc.TokenEndpointAuthMethod != "" && doc.TokenEndpointAuthMethod != "none" {
		return zero, fmt.Errorf("client metadata requires unsupported token_endpoint_auth_method: %s", doc.TokenEndpointAuthMethod)
	}

	md := CIMDClientMetadata{
		ClientID:                doc.ClientID,
		ClientName:              doc.ClientName,
		RedirectURIs:            doc.RedirectURIs,
		TokenEndpointAuthMethod: doc.TokenEndpointAuthMethod,
	}
	if md.TokenEndpointAuthMethod == "" {
		md.TokenEndpointAuthMethod = "none"
	}

	r.mu.Lock()
	r.cache[clientID] = cimdCacheEntry{metadata: md, fetchedAt: time.Now()}
	r.mu.Unlock()
	return md, nil
}

// cimdRejectedError wraps an error from CIMD resolution. Callers treat any
// error of this type like an unknown client rather than propagating the
// underlying fetch/validation error to the requester.
type cimdRejectedError struct{ err error }

func (e *cimdRejectedError) Error() string { return e.err.Error() }
func (e *cimdRejectedError) Unwrap() error { return e.err }

// isCIMDRejected reports whether err represents a failed CIMD resolution.
func isCIMDRejected(err error) bool {
	var target *cimdRejectedError
	return errors.As(err, &target)
}
