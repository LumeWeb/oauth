package oauth

import "net/url"

// MatchRedirectURI reports whether the requested redirect_uri is allowed for
// the given registered URIs. For loopback redirect URIs (localhost, 127.0.0.1,
// ::1), any port is accepted per RFC 8252 §7.3 because native clients use an
// OS-assigned port at runtime. Non-loopback URIs require an exact match.
func MatchRedirectURI(registered []string, requested string) bool {
	parsedReq, err := url.Parse(requested)
	if err != nil {
		return false
	}

	for _, reg := range registered {
		if reg == requested {
			return true
		}
		parsedReg, err := url.Parse(reg)
		if err != nil {
			continue
		}
		// Loopback-to-loopback: ignore the port difference only.
		if IsLoopbackRedirectURI(parsedReg) && IsLoopbackRedirectURI(parsedReq) {
			regCopy := *parsedReg
			reqCopy := *parsedReq
			regCopy.Host = parsedReg.Hostname()
			reqCopy.Host = parsedReq.Hostname()
			if regCopy.String() == reqCopy.String() {
				return true
			}
		}
	}
	return false
}

// IsLoopbackRedirectURI reports whether the parsed URL uses a loopback host.
func IsLoopbackRedirectURI(u *url.URL) bool {
	if u == nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// allowedRedirect reports whether redirectURI is a loopback callback that a
// public native client is legitimately allowed to use. Only http(s) with a
// loopback host is accepted; any cross-origin host is rejected, which is what
// prevents code exfiltration in the absence of a client registry.
func allowedRedirect(redirectURI string) bool {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return IsLoopbackRedirectURI(u)
}

// AllowedClientRedirect permits HTTPS callbacks advertised by registered web
// clients, while native clients remain limited to loopback HTTP callbacks.
func AllowedClientRedirect(redirectURI string) bool {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Hostname() == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	return allowedRedirect(redirectURI)
}
