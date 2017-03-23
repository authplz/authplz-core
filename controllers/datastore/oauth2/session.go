package oauth

import (
	"time"
)

// OauthSession session storage base type
// Used by grants for session storage
type OauthSession struct {
	UserID          uint
	UserExtID       string
	Username        string
	Subject         string
	AccessExpiry    time.Time
	RefreshExpiry   time.Time
	AuthorizeExpiry time.Time
	IDExpiry        time.Time
}

// NewSession creates an OauthSession with default expiry times
func NewSession(userID, username string) OauthSession {
	return OauthSession{
		UserExtID:       userID,
		Username:        username,
		AccessExpiry:    time.Time{},
		RefreshExpiry:   time.Time{},
		AuthorizeExpiry: time.Time{},
		IDExpiry:        time.Time{},
	}
}

func (s *OauthSession) GetSession() interface{} { return s }

// Getters and Setters

func (s *OauthSession) GetUserID() string              { return s.UserExtID }
func (s *OauthSession) GetUsername() string            { return s.Username }
func (s *OauthSession) GetSubject() string             { return s.Subject }
func (s *OauthSession) SetAccessExpiry(t time.Time)    { s.AccessExpiry = t }
func (s *OauthSession) GetAccessExpiry() time.Time     { return s.AccessExpiry }
func (s *OauthSession) SetRefreshExpiry(t time.Time)   { s.RefreshExpiry = t }
func (s *OauthSession) GetRefreshExpiry() time.Time    { return s.RefreshExpiry }
func (s *OauthSession) SetAuthorizeExpiry(t time.Time) { s.AuthorizeExpiry = t }
func (s *OauthSession) GetAuthorizeExpiry() time.Time  { return s.AuthorizeExpiry }
func (s *OauthSession) SetIDExpiry(t time.Time)        { s.IDExpiry = t }
func (s *OauthSession) GetIDExpiry() time.Time         { return s.IDExpiry }
