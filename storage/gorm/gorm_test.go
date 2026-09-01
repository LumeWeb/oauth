package gorm

import (
	"errors"
	"testing"
	"time"

	"go.lumeweb.com/oauth"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newTestStorage(t *testing.T) (*Storage, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// An in-memory SQLite DB is per-connection, so cap the pool at a single
	// connection to keep the shared schema/data visible across goroutines.
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("raw db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	// Tests migrate the schema; the adapter itself never migrates.
	if err := db.AutoMigrate(
		&OAuthClient{},
		&OAuthAuthorizationCode{},
		&OAuthRefreshToken{},
		&OAuthAccessToken{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg := oauth.DefaultConfig()
	cfg.Issuer = "https://auth.example.com"
	s, err := New(db, cfg)
	if err != nil {
		t.Fatalf("new storage: %v", err)
	}
	return s, db
}

func TestClientCRUD(t *testing.T) {
	s, _ := newTestStorage(t)

	c := oauth.Client{
		ClientID:          "client_1",
		ClientURI:         "https://resolver.example/md",
		ClientName:        "web",
		RedirectURIs:      []string{"https://app.example.com/cb"},
		GrantTypes:        []string{"authorization_code"},
		ResponseTypes:     []string{"code"},
		TokenEndpointAuth: "none",
		IsActive:          true,
	}
	if err := s.SaveClient(c); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.GetClient("client_1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ClientName != "web" || got.ClientURI != "https://resolver.example/md" || len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://app.example.com/cb" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if _, err := s.GetClient("nope"); !errors.Is(err, oauth.ErrClientNotFound) {
		t.Fatalf("expected ErrClientNotFound, got %v", err)
	}
	all, err := s.AllClients()
	if err != nil || len(all) != 1 {
		t.Fatalf("AllClients = %d, err %v", len(all), err)
	}
}

func TestClientUpsert(t *testing.T) {
	s, _ := newTestStorage(t)
	c := oauth.Client{
		ClientID:     "client_1",
		ClientURI:    "https://resolver.example/md",
		ClientName:   "web",
		RedirectURIs: []string{"https://app.example.com/cb"},
		IsActive:     true,
	}
	if err := s.SaveClient(c); err != nil {
		t.Fatalf("initial save: %v", err)
	}
	// Re-save the same client with updated fields (e.g. kill-switch toggle);
	// must update, not hit the unique index.
	c.ClientName = "web2"
	c.ClientURI = "https://resolver.example/rotated-md"
	c.IsActive = false
	c.RedirectURIs = []string{"https://app.example.com/cb2"}
	if err := s.SaveClient(c); err != nil {
		t.Fatalf("upsert save: %v", err)
	}
	got, err := s.GetClient("client_1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.IsActive || got.ClientName != "web2" || got.ClientURI != "https://resolver.example/rotated-md" || len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://app.example.com/cb2" {
		t.Fatalf("upsert did not apply updates: %+v", got)
	}
	all, _ := s.AllClients()
	if len(all) != 1 {
		t.Fatalf("expected exactly one client after upsert, got %d", len(all))
	}
}

func TestCodeSingleUse(t *testing.T) {
	s, _ := newTestStorage(t)
	code := oauth.AuthorizationCode{Code: "code1", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.SaveCode(code); err != nil {
		t.Fatalf("save code: %v", err)
	}
	if _, err := s.GetCode("code1"); err != nil {
		t.Fatalf("get code: %v", err)
	}
	if err := s.ConsumeCode("code1"); err != nil {
		t.Fatalf("consume: %v", err)
	}
	// Second consume is already-used.
	if err := s.ConsumeCode("code1"); !errors.Is(err, oauth.ErrCodeAlreadyUsed) {
		t.Fatalf("expected ErrCodeAlreadyUsed, got %v", err)
	}
	// GetCode on a used code reports not-found.
	if _, err := s.GetCode("code1"); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("expected ErrCodeNotFound for used code, got %v", err)
	}
	// Unknown code.
	if _, err := s.GetCode("missing"); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestRefreshRotation(t *testing.T) {
	s, _ := newTestStorage(t)
	if err := s.IssueRefreshToken("root", "client_a", "", "", 5); err != nil {
		t.Fatalf("issue root: %v", err)
	}
	clientID, _, _, _, successor, status, err := s.RotateRefreshToken("root", "client_a", "")
	if err != nil || status != oauth.RotateOK {
		t.Fatalf("rotate: status=%v err=%v", status, err)
	}
	if clientID != "client_a" || successor == "" {
		t.Fatalf("clientID=%q successor=%q", clientID, successor)
	}
	// In-window reuse returns the same successor.
	_, _, _, _, again, status, err := s.RotateRefreshToken("root", "client_a", "")
	if err != nil || status != oauth.RotateOKReused {
		t.Fatalf("reuse: status=%v err=%v", status, err)
	}
	if again != successor {
		t.Fatalf("in-window reuse expected same successor, got %q", again)
	}
	// Unknown token.
	if _, _, _, _, _, status, _ := s.RotateRefreshToken("nope", "", ""); status != oauth.RotateUnknown {
		t.Fatalf("unknown status=%v", status)
	}
}

// TestRefreshConcurrentFirstUseOnlyOneWins verifies that the GORM conditional
// UPDATE admits exactly one winner on concurrent first use.
func TestRefreshConcurrentFirstUseOnlyOneWins(t *testing.T) {
	s, _ := newTestStorage(t)
	if err := s.IssueRefreshToken("root", "client_a", "", "", 1); err != nil {
		t.Fatalf("issue root: %v", err)
	}
	const n = 32
	results := make(chan oauth.RotateStatus, n)
	for i := 0; i < n; i++ {
		go func() {
			_, _, _, _, _, st, _ := s.RotateRefreshToken("root", "client_a", "")
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
		t.Fatalf("expected exactly one RotateOK, got %d", okCount)
	}
	if other != 0 {
		t.Fatalf("expected no replay/unknown, got %d", other)
	}
	if reusedCount != n-1 {
		t.Fatalf("expected %d reuses, got %d", n-1, reusedCount)
	}
}

func TestAccessTokenCRUD(t *testing.T) {
	s, _ := newTestStorage(t)
	if err := s.SaveAccessToken(oauth.AccessToken{Token: "at", ClientID: "c", UserID: 3, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("save at: %v", err)
	}
	got, err := s.GetAccessToken("at")
	if err != nil || got.UserID != 3 {
		t.Fatalf("get at: %+v err=%v", got, err)
	}
	if _, err := s.GetAccessToken("missing"); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound, got %v", err)
	}
	if err := s.DeleteAccessToken("at"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetAccessToken("at"); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound after delete, got %v", err)
	}
}

func TestReap(t *testing.T) {
	s, _ := newTestStorage(t)
	now := time.Now()

	if err := s.IssueRefreshToken("expired-rt", "c", "", "", 1); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Backdate the refresh token to expired.
	if err := s.db.Model(&OAuthRefreshToken{}).Where("token = ?", "expired-rt").Update("expires_at", now.Add(-time.Hour)).Error; err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if err := s.SaveAccessToken(oauth.AccessToken{Token: "expired-at", ClientID: "c", ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatalf("save at: %v", err)
	}
	if err := s.SaveCode(oauth.AuthorizationCode{Code: "expired-code", ClientID: "c", ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatalf("save code: %v", err)
	}

	if err := s.Reap(now); err != nil {
		t.Fatalf("reap: %v", err)
	}
	if _, _, _, _, _, status, _ := s.RotateRefreshToken("expired-rt", "", ""); status != oauth.RotateUnknown {
		t.Fatalf("expected rotated expired root gone, status=%v", status)
	}
	if _, err := s.GetAccessToken("expired-at"); !errors.Is(err, oauth.ErrTokenNotFound) {
		t.Fatalf("expected expired at gone, got %v", err)
	}
	if _, err := s.GetCode("expired-code"); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("expected expired code gone, got %v", err)
	}
}

func TestRestartRepopulation(t *testing.T) {
	s, _ := newTestStorage(t)
	if err := s.SaveClient(oauth.Client{ClientID: "c1", RedirectURIs: []string{"https://a/cb"}}); err != nil {
		t.Fatalf("save client: %v", err)
	}
	if err := s.SaveAccessToken(oauth.AccessToken{Token: "t1", ClientID: "c1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("save at: %v", err)
	}
	clients, err := s.AllClients()
	if err != nil || len(clients) != 1 || clients[0].ClientID != "c1" {
		t.Fatalf("AllClients: %+v err %v", clients, err)
	}
	toks, err := s.AllAccessTokens()
	if err != nil || len(toks) != 1 || toks[0].Token != "t1" {
		t.Fatalf("AllAccessTokens: %+v err %v", toks, err)
	}
}

// TestScopeRoundTrip verifies the granted scope survives persistence and
// rotation in the production GORM adapter, so a resource server can enforce
// scope requirements against tokens read back after a restart or refresh.
func TestScopeRoundTrip(t *testing.T) {
	s, _ := newTestStorage(t)

	if err := s.SaveAccessToken(oauth.AccessToken{
		Token:     "at1",
		ClientID:  "c1",
		Resource:  "https://mcp.example.com",
		UserID:    7,
		Scope:     "read write",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("save access token: %v", err)
	}
	at, err := s.GetAccessToken("at1")
	if err != nil {
		t.Fatalf("get access token: %v", err)
	}
	if at.Scope != "read write" || at.Resource != "https://mcp.example.com" {
		t.Fatalf("access token scope/resource lost: %+v", at)
	}

	if err := s.IssueRefreshToken("rt-root", "c1", "https://mcp.example.com", "read write", 7); err != nil {
		t.Fatalf("issue refresh token: %v", err)
	}
	clientID, userID, resource, scope, successor, status, err := s.RotateRefreshToken("rt-root", "", "")
	if err != nil || status != oauth.RotateOK {
		t.Fatalf("rotate: status=%v err=%v", status, err)
	}
	if clientID != "c1" || userID != 7 || resource != "https://mcp.example.com" || scope != "read write" {
		t.Fatalf("rotation lost binding/scope: client=%q userID=%d resource=%q scope=%q", clientID, userID, resource, scope)
	}
	if successor == "" {
		t.Fatal("expected a successor token")
	}

	// Two-hop rotation: the successor's successor must still carry the scope,
	// guarding against a hop that drops granted permissions.
	_, _, _, scope2, successor2, status2, err := s.RotateRefreshToken(successor, "", "")
	if err != nil || status2 != oauth.RotateOK {
		t.Fatalf("second rotate: status=%v err=%v", status2, err)
	}
	if scope2 != "read write" {
		t.Fatalf("second-hop scope lost: got %q, want %q", scope2, "read write")
	}
	if successor2 == "" {
		t.Fatal("expected a second successor token")
	}
}
