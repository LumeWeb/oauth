package oauth

import (
	"testing"
	"time"
)

// rotationServer returns an AuthorizationServer backed by the in-package
// testStore, which implements the rotation semantics the facade translates.
func rotationServer() *AuthorizationServer {
	cfg := DefaultConfig()
	cfg.Issuer = "https://auth.example.com"
	return NewAuthorizationServer(cfg, newTestStore())
}

func newRefreshChain(t *testing.T, s *AuthorizationServer) (root string) {
	t.Helper()
	refresh := NewToken(32)
	if err := s.store.IssueRefreshToken(refresh, "client_a", "", 7); err != nil {
		t.Fatalf("issue root: %v", err)
	}
	return refresh
}

func TestRefreshFirstUseRotatesSuccessor(t *testing.T) {
	s := rotationServer()
	root := newRefreshChain(t, s)

	clientID, _, successor, status, err := s.store.RotateRefreshToken(root, "client_a", "")
	if err != nil || status != RotateOK {
		t.Fatalf("rotate: status=%v err=%v", status, err)
	}
	if clientID != "client_a" {
		t.Fatalf("clientID = %q, want client_a", clientID)
	}
	if successor == "" || successor == root {
		t.Fatal("expected a fresh successor distinct from the root")
	}
}

func TestRefreshInWindowReuseReturnsSameSuccessor(t *testing.T) {
	s := rotationServer()
	root := newRefreshChain(t, s)

	_, _, first, _, err := s.store.RotateRefreshToken(root, "client_a", "")
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	// Re-present the already-rotated root within the reuse window. The SAME
	// successor must be returned — never a fresh mint.
	_, _, second, status, err := s.store.RotateRefreshToken(root, "client_a", "")
	if err != nil || status != RotateOKReused {
		t.Fatalf("reuse rotate: status=%v err=%v", status, err)
	}
	if second != first {
		t.Fatalf("in-window reuse returned a different successor (%q vs %q)", second, first)
	}
}

func TestRefreshBeyondWindowReuseRevokesChain(t *testing.T) {
	s := rotationServer()
	root := newRefreshChain(t, s)

	_, _, successor, _, err := s.store.RotateRefreshToken(root, "client_a", "")
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	// Age the already-used root past the reuse window so re-presenting it is a
	// replay rather than a benign race.
	ts := s.store.(*testStore)
	rt := ts.refreshTokens[root]
	past := rt.UsedAt.Add(-(time.Minute))
	rt.UsedAt = &past
	ts.refreshTokens[root] = rt

	_, _, _, status, err := s.store.RotateRefreshToken(root, "client_a", "")
	if err != nil || status != RotateReplay {
		t.Fatalf("replay rotate: status=%v err=%v", status, err)
	}
	// The whole chain must now be revoked: presenting the successor fails too.
	if _, _, _, status, _ := s.store.RotateRefreshToken(successor, "client_a", ""); status != RotateReplay {
		t.Fatalf("successor of a revoked chain should be RotateReplay, got %v", status)
	}
}

func TestRefreshRevokedTokenReplay(t *testing.T) {
	s := rotationServer()
	root := newRefreshChain(t, s)
	s.store.RevokeChain(root)

	_, _, _, status, err := s.store.RotateRefreshToken(root, "client_a", "")
	if err != nil || status != RotateReplay {
		t.Fatalf("revoked rotate: status=%v err=%v", status, err)
	}
}

func TestRefreshExpiredTokenReplay(t *testing.T) {
	s := rotationServer()
	root := newRefreshChain(t, s)
	// Expire it directly in the test store.
	ts := s.store.(*testStore)
	rt := ts.refreshTokens[root]
	rt.ExpiresAt = time.Now().Add(-time.Minute)
	ts.refreshTokens[root] = rt

	_, _, _, status, err := s.store.RotateRefreshToken(root, "client_a", "")
	if err != nil || status != RotateReplay {
		t.Fatalf("expired rotate: status=%v err=%v", status, err)
	}
}

func TestRefreshBindingMismatchReplay(t *testing.T) {
	s := rotationServer()
	root := newRefreshChain(t, s)

	t.Run("client mismatch", func(t *testing.T) {
		_, _, _, status, _ := s.store.RotateRefreshToken(root, "evil_client", "")
		if status != RotateReplay {
			t.Fatalf("client mismatch should yield RotateReplay, got %v", status)
		}
	})
	t.Run("resource mismatch", func(t *testing.T) {
		// The token must be bound to a resource for a mismatch to be detected.
		bound := NewToken(32)
		if err := s.store.IssueRefreshToken(bound, "client_a", "https://auth.example.com", 7); err != nil {
			t.Fatalf("issue bound root: %v", err)
		}
		_, _, _, status, _ := s.store.RotateRefreshToken(bound, "client_a", "https://evil.example.com")
		if status != RotateReplay {
			t.Fatalf("resource mismatch should yield RotateReplay, got %v", status)
		}
	})
	t.Run("unknown token", func(t *testing.T) {
		_, _, _, status, _ := s.store.RotateRefreshToken("no-such-token", "", "")
		if status != RotateUnknown {
			t.Fatalf("unknown token should yield RotateUnknown, got %v", status)
		}
	})
}

func TestRefreshConcurrentFirstUseOnlyOneWins(t *testing.T) {
	s := rotationServer()
	root := newRefreshChain(t, s)

	statuses := make(chan RotateStatus, 64)
	for i := 0; i < 64; i++ {
		go func() {
			_, _, _, st, _ := s.store.RotateRefreshToken(root, "client_a", "")
			statuses <- st
		}()
	}
	var okCount, reusedCount, other int
	for i := 0; i < 64; i++ {
		switch <-statuses {
		case RotateOK:
			okCount++
		case RotateOKReused:
			reusedCount++
		default:
			other++
		}
	}
	if okCount != 1 {
		t.Fatalf("expected exactly one RotateOK winner, got %d", okCount)
	}
	if other != 0 {
		t.Fatalf("expected no replay/unknown in concurrent first-use, got %d", other)
	}
	if reusedCount != 63 {
		t.Fatalf("expected 63 in-window reuses, got %d", reusedCount)
	}
}
