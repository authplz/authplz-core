// Test storage interface for OSIN Oauth2
// From Osin package, but not exposed so copied here.

package oauth

import (
	"bytes"
	"encoding/gob"
	"github.com/ory-am/fosite"
	"time"
)

type MockSession struct {
	Username        string
	Subject         string
	AccessExpiry    time.Time
	RefreshExpiry   time.Time
	AuthorizeExpiry time.Time
	IDExpiry        time.Time
}

func (s *MockSession) GetUsername() string            { return s.Username }
func (s *MockSession) GetSubject() string             { return s.Subject }
func (s *MockSession) SetAccessExpiry(t time.Time)    { s.AccessExpiry = t }
func (s *MockSession) GetAccessExpiry() time.Time     { return s.AccessExpiry }
func (s *MockSession) SetRefreshExpiry(t time.Time)   { s.RefreshExpiry = t }
func (s *MockSession) GetRefreshExpiry() time.Time    { return s.RefreshExpiry }
func (s *MockSession) SetAuthorizeExpiry(t time.Time) { s.AuthorizeExpiry = t }
func (s *MockSession) GetAuthorizeExpiry() time.Time  { return s.AuthorizeExpiry }
func (s *MockSession) SetIDExpiry(t time.Time)        { s.IDExpiry = t }
func (s *MockSession) GetIDExpiry() time.Time         { return s.IDExpiry }

type SessionWrap struct {
	Session
}

func NewSessionWrap(s interface{}) *SessionWrap {
	return &SessionWrap{s.(Session)}
}

func (session *SessionWrap) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	switch key {
	case fosite.AccessToken:
		session.SetAccessExpiry(exp)
	case fosite.RefreshToken:
		session.SetRefreshExpiry(exp)
	case fosite.AuthorizeCode:
		session.SetAuthorizeExpiry(exp)
	case fosite.IDToken:
		session.SetIDExpiry(exp)
	}
}

func (session *SessionWrap) GetExpiresAt(key fosite.TokenType) time.Time {
	switch key {
	case fosite.AccessToken:
		return session.GetAccessExpiry()
	case fosite.RefreshToken:
		return session.GetRefreshExpiry()
	case fosite.AuthorizeCode:
		return session.GetAuthorizeExpiry()
	case fosite.IDToken:
		return session.GetIDExpiry()
	}
	return time.Time{}
}

func (s *SessionWrap) GetUsername() string {
	return s.GetUsername()
}

func (s *SessionWrap) GetSubject() string {
	return s.GetSubject()
}

func (s *SessionWrap) Clone() fosite.Session {
	var clone SessionWrap
	var mod bytes.Buffer
	enc := gob.NewEncoder(&mod)
	dec := gob.NewDecoder(&mod)
	_ = enc.Encode(s)
	_ = dec.Decode(&clone)

	return &clone
}
