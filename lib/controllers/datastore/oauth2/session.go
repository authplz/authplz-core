package oauthstore

import (
	"bytes"
	"encoding/gob"
	"time"
)

func init() {
	gob.Register(&OauthSession{})
}

// OauthSession session storage base type
// Used by grants for session storage
type OauthSession struct {
	UserExtID       string
	Username        string
	Subject         string
	AccessExpiry    time.Time
	RefreshExpiry   time.Time
	AuthorizeExpiry time.Time
	IDExpiry        time.Time
}

// NewSession creates an OauthSession
func NewSession(userID, username string) OauthSession {
	return OauthSession{
		UserExtID: userID,
		Username:  username,
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

func (s *OauthSession) Clone() interface{} {
	clone := OauthSession{}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)
	_ = enc.Encode(s)
	_ = dec.Decode(&clone)

	return &clone
}
