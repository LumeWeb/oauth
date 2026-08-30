package oauth

import "strings"

// ASMetadata is the RFC 8414 authorization server metadata document.
type ASMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	// ClientIDMetadataDocumentSupported optionally advertises support for
	// clients providing a Client ID Metadata Document URL. It is omitted by
	// default because CIMD resolution itself lives in the consumer, not this
	// library; a consumer that implements CIMD sets this to advertise it.
	ClientIDMetadataDocumentSupported *bool `json:"client_id_metadata_document_supported,omitempty"`
}

// BuildASMetadata constructs the RFC 8414 metadata for the given issuer/base
// URL. It advertises both dynamic client registration (registration_endpoint)
// and the standard grant/response types so no client class stalls after
// discovery. Endpoints are derived from the issuer per RFC 8414 §3.
func BuildASMetadata(cfg Config) ASMetadata {
	base := strings.TrimRight(cfg.Issuer, "/")
	return ASMetadata{
		Issuer:                cfg.Issuer,
		AuthorizationEndpoint: base + "/oauth/authorize",
		TokenEndpoint:         base + "/oauth/token",
		RegistrationEndpoint:  base + "/oauth/register",
		ResponseTypesSupported: []string{
			"code",
		},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"none",
		},
		CodeChallengeMethodsSupported: []string{
			"S256",
		},
		ScopesSupported: []string{
			"offline_access",
		},
	}
}

// ProtectedResourceMetadata is the RFC 9728 protected-resource metadata
// document.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported"`
}

// BuildProtectedResourceMetadata constructs RFC 9728 metadata for the given
// resource URL, pointing clients back at the AS issuer.
func BuildProtectedResourceMetadata(resourceURL, issuer string) ProtectedResourceMetadata {
	return ProtectedResourceMetadata{
		Resource:             resourceURL,
		AuthorizationServers: []string{issuer},
		BearerMethodsSupported: []string{
			"header",
		},
		ScopesSupported: []string{
			"offline_access",
		},
	}
}

// BuildProtectedResourceMetadataFromResource constructs RFC 9728 metadata from
// a registered Resource, using its scopes when present. It always points the
// AuthorizationServers field back at the AS issuer.
func BuildProtectedResourceMetadataFromResource(reg Resource, issuer string) ProtectedResourceMetadata {
	meta := BuildProtectedResourceMetadata(reg.ResourceURL, issuer)
	if len(reg.Scopes) > 0 {
		meta.ScopesSupported = reg.Scopes
	}
	return meta
}
