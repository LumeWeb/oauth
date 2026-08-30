package memory

import (
	"errors"
	"testing"
	"time"

	"go.lumeweb.com/oauth"
)

func newTest(t *testing.T) *Storage {
	t.Helper()
	return New(oauth.DefaultConfig())
}

func TestClientCRUD(t *testing.T) {
	s := newTest(t)
	if err := s.SaveClient(oauth.Client{ClientID: "c1", RedirectURIs: []string{"https://a/cb"}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.GetClient("c1")
	if err != nil || len(got.RedirectURIs) != 1 {
		t.Fatalf("get: %+v err %v", got, err)
	}
	if _, err := s.GetClient("nope"); !errors.Is(err, oauth.ErrClientNotFound) {
		t.Fatalf("expected ErrClientNotFound, got %v", err)
	}
	all, _ := s.AllClients()
	if len(all) != 1 {
		t.Fatalf("AllClients len = %d", len(all))
	}
}

func TestCodeSingleUse(t *testing.T) {
	s := newTest(t)
	if err := s.SaveCode(oauth.AuthorizationCode{Code: "code1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.ConsumeCode("code1"); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := s.ConsumeCode("code1"); !errors.Is(err, oauth.ErrCodeAlreadyUsed) {
		t.Fatalf("expected ErrCodeAlreadyUsed, got %v", err)
	}
	if _, err := s.GetCode("code1"); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("expected ErrCodeNotFound for used code, got %v", err)
	}
	if _, err := s.GetCode("missing"); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestRefreshRotationAndReuse(t *testing.T) {
	s := newTest(t)
	if err := s.IssueRefreshToken("root", "client_a", "", 5); err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, _, _, successor, status, err := s.RotateRefreshToken("root", "client_a", "")
	if err != nil || status != oauth.RotateOK {
		t.Fatalf("rotate: status=%v err=%v", status, err)
	}
	_, _, _, again, status, err := s.RotateRefreshToken("root", "client_a", "")
	if err != nil || status != oauth.RotateOKReused || again != successor {
		t.Fatalf("reuse: status=%v again=%q err=%v", status, again, err)
	}
	if _, _, _, _, status, _ := s.RotateRefreshToken("nope", "", ""); status != oauth.RotateUnknown {
		t.Fatalf("unknown status=%v", status)
	}
}

// TestRefreshBeyondWindowReplayRevokesChain exercises the replay-detection
// path that calls RevokeChain while the rotation lock is held. It must not
// deadlock and must revoke the whole chain.
func TestRefreshBeyondWindowReplayRevokesChain(t *testing.T) {
	s := newTest(t)
	if err := s.IssueRefreshToken("root", "client_a", "", 4); err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, _, _, successor, status, err := s.RotateRefreshToken("root", "client_a", "")
	if err != nil || status != oauth.RotateOK {
		t.Fatalf("first rotate: status=%v err=%v", status, err)
	}
	// Age the already-used root past the reuse window so re-presenting it is a
	// replay, not a benign race.
	rt := s.refreshTokens["root"]
	past := rt.UsedAt.Add(-(time.Minute))
	rt.UsedAt = &past
	s.refreshTokens["root"] = rt

	_, _, _, _, status, err = s.RotateRefreshToken("root", "client_a", "")
	if err != nil || status != oauth.RotateReplay {
		t.Fatalf("replay rotate: status=%v err=%v", status, err)
	}
	// Chain must be fully revoked: the successor is now rejected too.
	if _, _, _, _, status, _ := s.RotateRefreshToken(successor, "client_a", ""); status != oauth.RotateReplay {
		t.Fatalf("successor of revoked chain should be RotateReplay, got %v", status)
	}
}

func TestAccessTokenCRUD(t *testing.T) {
	s := newTest(t)
	if err := s.SaveAccessToken(oauth.AccessToken{Token: "at", ClientID: "c", UserID: 3}); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.GetAccessToken("at")
	if err != nil || got.UserID != 3 {
		t.Fatalf("get: %+v err %v", got, err)
	}
	if _, err := s.GetAccessToken("missing"); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound, got %v", err)
	}
}

func TestConcurrentFirstUseOnlyOneWins(t *testing.T) {
	s := newTest(t)
	if err := s.IssueRefreshToken("root", "client_a", "", 1); err != nil {
		t.Fatalf("issue: %v", err)
	}
	const n = 64
	results := make(chan oauth.RotateStatus, n)
	for i := 0; i < n; i++ {
		go func() {
			_, _, _, _, st, _ := s.RotateRefreshToken("root", "client_a", "")
			results <- st
		}()
	}
	var okCount, reusedCount, other int
	for i := 0; i < n; i++ {
		switch <-results {
		case oauth.RotateOK:
			okCount++
		case oauth.RotateOKReused:
			reusedCount++
		default:
			other++
		}
	}
	if okCount != 1 {
		t.Fatalf("expected 1 RotateOK, got %d", okCount)
	}
	if other != 0 {
		t.Fatalf("expected no replay/unknown, got %d", other)
	}
	if reusedCount != n-1 {
		t.Fatalf("expected %d reuses, got %d", n-1, reusedCount)
	}
}

func TestReap(t *testing.T) {
	s := newTest(t)
	now := time.Now()
	if err := s.SaveCode(oauth.AuthorizationCode{Code: "expired", ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.SaveAccessToken(oauth.AccessToken{Token: "expired-at", ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatalf("save at: %v", err)
	}
	if err := s.IssueRefreshToken("expired-rt", "c", "", 1); err != nil {
		t.Fatalf("issue: %v", err)
	}
	rt := s.refreshTokens["expired-rt"]
	rt.ExpiresAt = now.Add(-time.Hour)
	s.refreshTokens["expired-rt"] = rt

	if err := s.Reap(now); err != nil {
		t.Fatalf("reap: %v", err)
	}
	if _, err := s.GetCode("expired"); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("expected expired code gone, got %v", err)
	}
	if _, err := s.GetAccessToken("expired-at"); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Fatalf("expected expired at gone, got %v", err)
	}
	if _, _, _, _, status, _ := s.RotateRefreshToken("expired-rt", "", ""); status != oauth.RotateUnknown {
		t.Fatalf("expected expired rt gone, status=%v", status)
	}
}
