package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	// cimdFetchTimeout bounds the outbound GET and its dial/handshake so a
	// slow or hostile host cannot stall the authorize flow.
	cimdFetchTimeout = 10 * time.Second
	// cimdMaxBodyBytes caps the document size read from the wire.
	cimdMaxBodyBytes = 64 * 1024
)

// CIMDResolver resolves URL-form client_ids (RFC 9291) into client metadata
// documents. It is the resolution half of AS-level CIMD support.
//
// Every fetch is gated by a mandatory SSRF gate that is always on and does not
// name products: the client_id must be an https URL, the host is resolved to
// an IP that must be globally routable (private, loopback, link-local and
// metadata addresses are refused), redirects are not followed, and there are
// size and time limits. An optional host allowlist may additionally restrict
// which metadata origins may act as clients; with an empty allowlist (the
// default) any public https URL that survives the SSRF gate is accepted and
// the domain is surfaced to the user on the consent screen.
//
// Resolution requires outbound networking, so unlike the rest of this package
// it is not pure domain logic; it is used only by a consumer that opts in via
// AuthorizationServer.WithCIMDResolver.
type CIMDResolver struct {
	// allowedHosts is an optional allowlist of hosts whose CIMD documents may
	// be fetched. When empty, any host that passes the SSRF gate is accepted.
	allowedHosts map[string]struct{}
	cache        map[string]cimdCacheEntry
	ttl          time.Duration
	client       *http.Client
	// lookupAddr resolves a host once; the returned address is the exact IP
	// that is dialed, avoiding a second resolution that a rebinding attacker
	// could point at a private address. It defaults to
	// net.DefaultResolver.LookupIPAddr and is the test seam for the SSRF gate.
	lookupAddr func(ctx context.Context, host string) ([]net.IPAddr, error)
	mu         sync.Mutex
}

// NewCIMDResolver returns a resolver with no host allowlist (any public https
// URL that passes the SSRF gate is accepted) and a fresh empty cache.
func NewCIMDResolver() *CIMDResolver {
	r := &CIMDResolver{
		allowedHosts: make(map[string]struct{}),
		cache:        make(map[string]cimdCacheEntry),
		ttl:          cimdCacheTTL,
		lookupAddr:   net.DefaultResolver.LookupIPAddr,
	}
	r.client = &http.Client{
		Timeout: cimdFetchTimeout,
		// CIMD documents are fetched from the exact URL the client sent.
		// Following a redirect could smuggle the fetch to an unvalidated host
		// after the SSRF gate has passed, so any redirect is treated as an
		// error.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// Disable the environment proxy so the SSRF gate is the sole control
		// over where the fetch connects.
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         r.dialContext,
			TLSHandshakeTimeout: cimdFetchTimeout / 2,
			ForceAttemptHTTP2:   true,
		},
	}
	return r
}

// AllowHost adds hosts to the resolver's optional allowlist. With a non-empty
// allowlist, only the listed hosts may act as CIMD clients; with an empty
// allowlist any public https host that survives the SSRF gate is accepted.
// It is safe to call concurrently with Resolve.
func (r *CIMDResolver) AllowHost(hosts ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, h := range hosts {
		if h != "" {
			r.allowedHosts[h] = struct{}{}
		}
	}
}

// IsClientIDDocumentURL reports whether clientID is a URL-form client
// identifier that should be resolved as a CIMD document (RFC 9291 §3). Per the
// spec the URL must use https and contain a path component.
func (r *CIMDResolver) IsClientIDDocumentURL(clientID string) bool {
	u, err := url.Parse(clientID)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != "" && u.Path != "" && u.Path != "/"
}

// allowedHost reports whether the URL's host is permitted by the optional
// allowlist. An empty allowlist means open: any host that survives the SSRF
// gate is accepted. A non-empty allowlist rejects every host not listed.
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
	defer r.mu.Unlock()
	if len(r.allowedHosts) == 0 {
		return true
	}
	_, ok := r.allowedHosts[host]
	return ok
}

// isPublicRoutableIP reports whether ip is a globally routable unicast
// address. It refuses private, loopback, link-local (which includes cloud
// metadata endpoints such as 169.254.169.254), multicast and unspecified
// addresses, plus reserved IPv4 ranges that are not globally routable.
func isPublicRoutableIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		// net.IP.IsPrivate only covers RFC 1918/4193, so the shared (CGNAT,
		// 100.64.0.0/10) and benchmarking (198.18.0.0/15) ranges that are not
		// globally routable need an explicit check.
		if (ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127) ||
			(ip4[0] == 198 && ip4[1]&0xfe == 18) {
			return false
		}
	}
	return true
}

// dialContext resolves host to a publicly routable IP and dials that exact IP,
// bypassing the standard re-resolution the HTTP client would otherwise perform.
// Resolving and dialing the same validated address closes the DNS-rebinding
// window where a check-time address could differ from the connect-time address.
func (r *CIMDResolver) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata address %q: %w", addr, err)
	}
	addrs, err := r.lookupAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("could not resolve metadata host %q: %w", host, err)
	}
	for _, a := range addrs {
		if !isPublicRoutableIP(a.IP) {
			continue
		}
		d := net.Dialer{Timeout: cimdFetchTimeout / 2}
		return d.DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
	}
	return nil, fmt.Errorf("metadata host %q resolves only to non-public addresses", host)
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

	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path == "" || u.Path == "/" {
		return zero, errors.New("client metadata URL must be an https URL with a path")
	}
	if !r.allowedHost(clientID) {
		return zero, errors.New("client metadata host is not allowlisted")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return zero, fmt.Errorf("could not build client metadata request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
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
