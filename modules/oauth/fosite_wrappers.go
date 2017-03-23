package oauth

import (
	"bytes"
	"encoding/gob"
	"github.com/ory-am/fosite"
	"time"
)

// ClientWrapper overrides Client interface with Fosite specific types
type ClientWrapper struct {
	Client
}

// NewClientWrapper creates a client wrapper around a Client interface object to support the methods required by Fosite
func NewClientWrapper(c interface{}) *ClientWrapper {
	return &ClientWrapper{c.(Client)}
}

func (c ClientWrapper) GetHashedSecret() []byte {
	return []byte(c.Client.GetSecret())
}

func (c ClientWrapper) GetRedirectURIs() []string {
	return c.Client.GetRedirectURIs()
}
func (c ClientWrapper) GetGrantTypes() fosite.Arguments {
	return fosite.Arguments(c.Client.GetGrantTypes())
}
func (c ClientWrapper) GetResponseTypes() fosite.Arguments {
	return fosite.Arguments(c.Client.GetResponseTypes())
}
func (c ClientWrapper) GetScopes() fosite.Arguments {
	return fosite.Arguments(c.Client.GetScopes())
}

// SessionWrap overrides the Session interface with Fosite specific types
type SessionWrap struct {
	UserSession
}

// NewSessionWrap creates a session wrapper around a session object to support the methods required by fosite
func NewSessionWrap(s interface{}) *SessionWrap {
	return &SessionWrap{s.(UserSession)}
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
