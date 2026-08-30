package oauth

import (
	"errors"
	"testing"
)

func TestRegisterResourceEnablesResourceValidation(t *testing.T) {
	s := testServer()
	redirect := "https://app.example.com/cb"
	client := mustRegisterClient(t, s, redirect)

	// A resource bound to a URL that is neither the issuer nor registered is
	// rejected.
	req := validAuthorizeRequest(client.ClientID, redirect)
	req.Resource = "https://research.example.com/data"
	assertResourceRejected(t, s, req)

	// Registering the resource makes the same request valid.
	s.RegisterResource(Resource{
		ResourceURL: "https://research.example.com/data",
		Scopes:      []string{"offline_access"},
	})
	if err := s.ValidateAuthorizeRequest(req); err != nil {
		t.Fatalf("expected request bound to a registered resource to pass: %v", err)
	}
}

func TestResourceRegistryLifecycle(t *testing.T) {
	s := testServer()
	url := "https://research.example.com/data"

	if _, ok := s.GetResource(url); ok {
		t.Fatalf("GetResource(%q) = found before registration, want not found", url)
	}
	if got := len(s.ListResources()); got != 0 {
		t.Fatalf("ListResources before registration = %d entries, want 0", got)
	}

	s.RegisterResource(Resource{ResourceURL: url, Scopes: []string{"s1"}})

	reg, ok := s.GetResource(url)
	if !ok {
		t.Fatalf("GetResource(%q) not found after registration", url)
	}
	if reg.ResourceURL != url {
		t.Fatalf("GetResource URL = %q, want %q", reg.ResourceURL, url)
	}
	if len(s.ListResources()) != 1 {
		t.Fatalf("ListResources after registration = %d entries, want 1", len(s.ListResources()))
	}

	// Registration is normalized by trimming trailing slashes.
	if _, ok := s.GetResource(url + "/"); !ok {
		t.Fatalf("GetResource with trailing slash did not match normalized registration")
	}

	s.UnregisterResource(url)
	if _, ok := s.GetResource(url); ok {
		t.Fatalf("GetResource(%q) still found after UnregisterResource", url)
	}
	if len(s.ListResources()) != 0 {
		t.Fatalf("ListResources after unregister = %d entries, want 0", len(s.ListResources()))
	}

	// Unregistering an unknown resource is a no-op.
	s.UnregisterResource("https://never-registered.example.com")
}

func TestValidateResourceCallback(t *testing.T) {
	redirect := "https://app.example.com/cb"

	t.Run("callback overrides default validation", func(t *testing.T) {
		s := testServer()
		client := mustRegisterClient(t, s, redirect)

		// A callback that accepts a fixed audience regardless of the issuer.
		s.cfg.ValidateResource = func(resource string) bool {
			return resource == "https://aud.example.com"
		}

		req := validAuthorizeRequest(client.ClientID, redirect)
		req.Resource = "https://aud.example.com"
		if err := s.ValidateAuthorizeRequest(req); err != nil {
			t.Fatalf("expected callback-accepted resource to pass: %v", err)
		}

		req.Resource = "https://issuer.example.com"
		if err := s.ValidateAuthorizeRequest(req); err == nil {
			t.Fatal("expected callback-rejected resource to fail even though it matches the issuer")
		}
	})
}

func TestBuildProtectedResourceMetadataFromResource(t *testing.T) {
	const displayName = "Lume Research Data"
	meta := BuildProtectedResourceMetadataFromResource(Resource{
		ResourceURL: "https://research.example.com/data",
		Scopes:      []string{"offline_access"},
		DisplayName: displayName,
	}, "https://auth.example.com")
	if meta.Resource != "https://research.example.com/data" {
		t.Fatalf("Resource = %q, want the registered URL", meta.Resource)
	}
	if meta.ResourceName != displayName {
		t.Fatalf("ResourceName = %q, want the registered display name", meta.ResourceName)
	}
	if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != "https://auth.example.com" {
		t.Fatalf("AuthorizationServers = %v, want the AS issuer", meta.AuthorizationServers)
	}
	if len(meta.ScopesSupported) != 1 || meta.ScopesSupported[0] != "offline_access" {
		t.Fatalf("ScopesSupported = %v, want the registered scopes", meta.ScopesSupported)
	}
}

// assertResourceRejected asserts that ValidateAuthorizeRequest rejects req with
// an invalid_request resource error.
func assertResourceRejected(t *testing.T, s *AuthorizationServer, req AuthorizeRequest) {
	t.Helper()
	var oerr *OAuthError
	if err := s.ValidateAuthorizeRequest(req); err == nil {
		t.Fatal("expected invalid resource to be rejected, but request passed")
	} else if !errors.As(err, &oerr) || oerr.Code != ErrInvalidRequest {
		t.Fatalf("expected invalid_request for invalid resource, got %v", err)
	}
}
