// Package gorm provides an oauth.Storage implementation backed by GORM.
//
// It does not manage its own schema or migrations. The exported model structs
// in models.go expose the expected schema, which consumers create themselves.
// The tables must already exist before constructing a Storage.
package gorm

import (
	"encoding/json"
	"errors"
	"time"

	"go.lumeweb.com/oauth"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Ensure Storage satisfies oauth.Storage at compile time.
var _ oauth.Storage = (*Storage)(nil)

// Storage implements oauth.Storage using GORM. It is safe for concurrent use
// through GORM's connection pool.
type Storage struct {
	db          *gorm.DB
	refreshTTL  time.Duration
	reuseWindow time.Duration
}

// New creates an oauth.Storage backed by the given *gorm.DB. The caller must
// have already created the OAuth tables (see models.go). The zero-valued
// refresh/reuse durations in cfg fall back to production-safe defaults.
func New(db *gorm.DB, cfg oauth.Config) (*Storage, error) {
	if db == nil {
		return nil, errors.New("gorm: nil *gorm.DB")
	}
	refreshTTL := cfg.RefreshTTL
	if refreshTTL <= 0 {
		refreshTTL = 720 * time.Hour
	}
	reuseWindow := cfg.ReuseWindow
	if reuseWindow <= 0 {
		reuseWindow = 30 * time.Second
	}
	return &Storage{db: db, refreshTTL: refreshTTL, reuseWindow: reuseWindow}, nil
}

// Close closes the underlying database connection pool.
func (s *Storage) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// ---- clients ----

// SaveClient persists a registered client, upserting on client_id so
// re-registration or field updates (e.g. toggling IsActive) do not collide
// with the unique index.
func (s *Storage) SaveClient(c oauth.Client) error {
	model := &OAuthClient{
		ClientID:          c.ClientID,
		ClientName:        c.ClientName,
		RedirectURIs:      mustJSON(c.RedirectURIs),
		GrantTypes:        mustJSON(c.GrantTypes),
		ResponseTypes:     mustJSON(c.ResponseTypes),
		TokenEndpointAuth: c.TokenEndpointAuth,
		Scopes:            mustJSON(c.Scopes),
		UserID:            c.UserID,
		IsActive:          c.IsActive,
	}
	// Update the mutable columns from the explicit values. Assigning from
	// `excluded` (AssignmentColumns) would re-apply the is_active DB default to
	// a false value, silently ignoring a deactivation; binding literal values
	// instead sets exactly what the caller passed.
	return s.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "client_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"client_name":                model.ClientName,
			"redirect_uris":              model.RedirectURIs,
			"grant_types":                model.GrantTypes,
			"response_types":             model.ResponseTypes,
			"token_endpoint_auth_method": model.TokenEndpointAuth,
			"scopes":                     model.Scopes,
			"user_id":                    model.UserID,
			"is_active":                  model.IsActive,
		}),
	}).Create(model).Error
}

// GetClient retrieves a client by ID, returning oauth.ErrClientNotFound if
// absent.
func (s *Storage) GetClient(clientID string) (oauth.Client, error) {
	var model OAuthClient
	if err := s.db.Where("client_id = ?", clientID).First(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return oauth.Client{}, oauth.ErrClientNotFound
		}
		return oauth.Client{}, err
	}
	return s.clientFromModel(model), nil
}

// AllClients returns every registered client.
func (s *Storage) AllClients() ([]oauth.Client, error) {
	var rows []OAuthClient
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]oauth.Client, 0, len(rows))
	for _, r := range rows {
		out = append(out, s.clientFromModel(r))
	}
	return out, nil
}

// ---- authorization codes ----

// SaveCode stores a new authorization code.
func (s *Storage) SaveCode(code oauth.AuthorizationCode) error {
	model := &OAuthAuthorizationCode{
		Code:                code.Code,
		ClientID:            code.ClientID,
		RedirectURI:         code.RedirectURI,
		CodeChallenge:       code.CodeChallenge,
		CodeChallengeMethod: code.CodeChallengeMethod,
		Resource:            code.Resource,
		UserID:              code.UserID,
		Scope:               code.Scope,
		ExpiresAt:           code.ExpiresAt,
		UsedAt:              code.UsedAt,
	}
	return s.db.Create(model).Error
}

// GetCode retrieves a code by value. Returns oauth.ErrCodeNotFound if absent
// or already used.
func (s *Storage) GetCode(code string) (oauth.AuthorizationCode, error) {
	var model OAuthAuthorizationCode
	if err := s.db.Where("code = ?", code).First(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return oauth.AuthorizationCode{}, oauth.ErrCodeNotFound
		}
		return oauth.AuthorizationCode{}, err
	}
	if model.UsedAt != nil {
		return oauth.AuthorizationCode{}, oauth.ErrCodeNotFound
	}
	return oauth.AuthorizationCode{
		Code:                model.Code,
		ClientID:            model.ClientID,
		RedirectURI:         model.RedirectURI,
		CodeChallenge:       model.CodeChallenge,
		CodeChallengeMethod: model.CodeChallengeMethod,
		Resource:            model.Resource,
		UserID:              model.UserID,
		Scope:               model.Scope,
		ExpiresAt:           model.ExpiresAt,
		UsedAt:              model.UsedAt,
	}, nil
}

// ConsumeCode atomically marks a code as used, enforcing single-use. Returns
// oauth.ErrCodeAlreadyUsed if already consumed.
func (s *Storage) ConsumeCode(code string) error {
	res := s.db.Model(&OAuthAuthorizationCode{}).
		Where("code = ? AND used_at IS NULL", code).
		Update("used_at", time.Now())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 1 {
		return nil
	}
	var count int64
	if err := s.db.Model(&OAuthAuthorizationCode{}).Where("code = ?", code).Count(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		return oauth.ErrCodeNotFound
	}
	return oauth.ErrCodeAlreadyUsed
}

// ---- refresh tokens ----

// IssueRefreshToken stores the initial refresh token of a new chain (the
// root). The root has no successor yet.
func (s *Storage) IssueRefreshToken(token, clientID, resource, scope string, userID uint) error {
	return s.issueInChain(token, "", clientID, resource, scope, token, userID)
}

// GetRefreshToken retrieves a refresh token by value, returning
// oauth.ErrRefreshTokenNotFound if absent.
func (s *Storage) GetRefreshToken(token string) (oauth.RefreshToken, error) {
	var model OAuthRefreshToken
	if err := s.db.Where("token = ?", token).First(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return oauth.RefreshToken{}, oauth.ErrRefreshTokenNotFound
		}
		return oauth.RefreshToken{}, err
	}
	return oauth.RefreshToken{
		Token:     model.Token,
		ClientID:  model.ClientID,
		Resource:  model.Resource,
		UserID:    model.UserID,
		Scope:     model.Scope,
		ChainRoot: model.ChainRoot,
		ExpiresAt: model.ExpiresAt,
		UsedAt:    model.UsedAt,
		Revoked:   model.Revoked,
		Successor: model.Successor,
	}, nil
}

// issueInChain stores a refresh token whose chain root is chainRoot. Successor
// tokens from rotation inherit the chain root of the token they rotate from so
// a whole grant chain can be revoked together.
func (s *Storage) issueInChain(token, successor, clientID, resource, scope, chainRoot string, userID uint) error {
	now := time.Now()
	return s.db.Create(&OAuthRefreshToken{
		Token:     token,
		ClientID:  clientID,
		Resource:  resource,
		UserID:    userID,
		Scope:     scope,
		ChainRoot: chainRoot,
		ExpiresAt: now.Add(s.refreshTTL),
		Successor: successor,
	}).Error
}

// RotateRefreshToken implements RFC 9700 §4.13 rotation + reuse detection.
// First use is claimed with a single conditional UPDATE of used_at and
// successor so only one concurrent presenter can win.
func (s *Storage) RotateRefreshToken(token, clientID, resource string) (string, uint, string, string, string, oauth.RotateStatus, error) {
	now := time.Now()
	// Retry when the winner's transaction rolled back and the token is still
	// unused.
	for attempt := 0; attempt < 3; attempt++ {
		var rt OAuthRefreshToken
		if err := s.db.Where("token = ?", token).First(&rt).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return "", 0, "", "", "", oauth.RotateUnknown, nil
			}
			return "", 0, "", "", "", oauth.RotateUnknown, err
		}
		if rt.Revoked || now.After(rt.ExpiresAt) {
			return "", 0, "", "", "", oauth.RotateReplay, nil
		}
		// Binding: presenting client and bound resource must match.
		if clientID != "" && rt.ClientID != clientID {
			return "", 0, "", "", "", oauth.RotateReplay, nil
		}
		if resource != "" && rt.Resource != "" && resource != rt.Resource {
			return "", 0, "", "", "", oauth.RotateReplay, nil
		}
		if rt.UsedAt != nil {
			// Already rotated; re-evaluate reuse-vs-replay.
			return s.resolvePostUse(rt, now)
		}
		succ := oauth.NewToken(32)
		var won bool
		err := s.db.Transaction(func(tx *gorm.DB) error {
			// Atomic first-use claim (used_at and successor together).
			res := tx.Model(&OAuthRefreshToken{}).
				Where("token = ? AND used_at IS NULL", rt.Token).
				Updates(map[string]interface{}{"used_at": now, "successor": succ})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 1 {
				return nil // lost the claim; no error
			}
			won = true
			// Won the claim: persist the successor in the same transaction. The
			// bound scope rides forward so a second rotation hop does not drop
			// granted permissions.
			return tx.Create(&OAuthRefreshToken{
				Token:     succ,
				ClientID:  rt.ClientID,
				Resource:  rt.Resource,
				UserID:    rt.UserID,
				Scope:     rt.Scope,
				ChainRoot: rt.ChainRoot,
				ExpiresAt: now.Add(s.refreshTTL),
			}).Error
		})
		if err != nil {
			return "", 0, "", "", "", oauth.RotateUnknown, err
		}
		if won {
			return rt.ClientID, rt.UserID, rt.Resource, rt.Scope, succ, oauth.RotateOK, nil
		}
		// Lost the claim; re-read and loop.
	}
	// Retries exhausted; decide on current state (unused -> unknown, not replay).
	var current OAuthRefreshToken
	if err := s.db.Where("token = ?", token).First(&current).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", 0, "", "", "", oauth.RotateUnknown, nil
		}
		return "", 0, "", "", "", oauth.RotateUnknown, err
	}
	if current.UsedAt == nil {
		return "", 0, "", "", "", oauth.RotateUnknown, nil
	}
	return s.resolvePostUse(current, now)
}

// resolvePostUse handles a token that has already been used/rotated. Within the
// reuse-detection window it is a benign race and the SAME successor issued at
// rotation time is returned (no extra tokens minted). Beyond the window the
// whole chain is revoked and the use rejected (replay).
func (s *Storage) resolvePostUse(rt OAuthRefreshToken, now time.Time) (string, uint, string, string, string, oauth.RotateStatus, error) {
	if rt.UsedAt == nil {
		return "", 0, "", "", "", oauth.RotateReplay, nil
	}
	if now.Sub(*rt.UsedAt) <= s.reuseWindow {
		if rt.Successor == "" {
			return "", 0, "", "", "", oauth.RotateReplay, nil
		}
		return rt.ClientID, rt.UserID, rt.Resource, rt.Scope, rt.Successor, oauth.RotateOKReused, nil
	}
	// Replay beyond the window: revoke the whole chain and reject.
	if err := s.RevokeChain(rt.ChainRoot); err != nil {
		return "", 0, "", "", "", oauth.RotateUnknown, err
	}
	return "", 0, "", "", "", oauth.RotateReplay, nil
}

// RevokeChain marks every token in a chain as revoked (RFC 7009).
func (s *Storage) RevokeChain(chainRoot string) error {
	return s.db.Model(&OAuthRefreshToken{}).
		Where("chain_root = ?", chainRoot).
		Update("revoked", true).Error
}

// ---- access tokens ----

// SaveAccessToken persists an access token and its expiry.
func (s *Storage) SaveAccessToken(token oauth.AccessToken) error {
	return s.db.Save(&OAuthAccessToken{
		Token:     token.Token,
		ClientID:  token.ClientID,
		Resource:  token.Resource,
		UserID:    token.UserID,
		Scope:     token.Scope,
		ExpiresAt: token.ExpiresAt,
	}).Error
}

// GetAccessToken retrieves an access token by value, returning
// oauth.ErrTokenNotFound if absent.
func (s *Storage) GetAccessToken(token string) (oauth.AccessToken, error) {
	var model OAuthAccessToken
	if err := s.db.Where("token = ?", token).First(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return oauth.AccessToken{}, oauth.ErrTokenNotFound
		}
		return oauth.AccessToken{}, err
	}
	return oauth.AccessToken{
		Token:     model.Token,
		ClientID:  model.ClientID,
		Resource:  model.Resource,
		UserID:    model.UserID,
		Scope:     model.Scope,
		ExpiresAt: model.ExpiresAt,
	}, nil
}

// DeleteAccessToken removes a single access token. It is idempotent.
func (s *Storage) DeleteAccessToken(token string) error {
	return s.db.Delete(&OAuthAccessToken{}, "token = ?", token).Error
}

// AllAccessTokens returns every persisted access token.
func (s *Storage) AllAccessTokens() ([]oauth.AccessToken, error) {
	var rows []OAuthAccessToken
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]oauth.AccessToken, 0, len(rows))
	for _, r := range rows {
		out = append(out, oauth.AccessToken{
			Token:     r.Token,
			ClientID:  r.ClientID,
			Resource:  r.Resource,
			UserID:    r.UserID,
			Scope:     r.Scope,
			ExpiresAt: r.ExpiresAt,
		})
	}
	return out, nil
}

// ---- lifecycle ----

// Reap deletes expired refresh tokens, access tokens, and authorization codes,
// plus stale clients.
func (s *Storage) Reap(now time.Time) error {
	if err := s.db.Where("expires_at < ?", now).Delete(&OAuthRefreshToken{}).Error; err != nil {
		return err
	}
	if err := s.db.Where("expires_at < ?", now).Delete(&OAuthAccessToken{}).Error; err != nil {
		return err
	}
	if err := s.db.Where("expires_at < ?", now).Delete(&OAuthAuthorizationCode{}).Error; err != nil {
		return err
	}
	return s.db.Where("created_at < ?", now.Add(-s.refreshTTL)).Delete(&OAuthClient{}).Error
}

// mustJSON encodes v as JSON, or "" if it cannot be marshaled. The domain
// fields are plain slices that always marshal successfully.
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// parseJSON decodes a stored JSON array string into out, returning an error on
// malformed data.
func parseJSON(raw string, out any) error {
	if raw == "" {
		return nil
	}
	return json.Unmarshal([]byte(raw), out)
}

func (s *Storage) clientFromModel(model OAuthClient) oauth.Client {
	client := oauth.Client{
		ClientID:          model.ClientID,
		ClientName:        model.ClientName,
		TokenEndpointAuth: model.TokenEndpointAuth,
		UserID:            model.UserID,
		IsActive:          model.IsActive,
	}
	_ = parseJSON(model.RedirectURIs, &client.RedirectURIs)
	_ = parseJSON(model.GrantTypes, &client.GrantTypes)
	_ = parseJSON(model.ResponseTypes, &client.ResponseTypes)
	_ = parseJSON(model.Scopes, &client.Scopes)
	return client
}
