package oauth

import (
	"github.com/ory-am/fosite"
	"net/url"
	"time"
)

// ClientWrapper overrides Client interface with Fosite specific types
type ClientWrapper struct {
	Client
}

// NewClientWrapper creates a client wrapper around a Client interface object to support the methods required by Fosite
func NewClientWrapper(c interface{}) fosite.Client {
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
func NewSessionWrap(s interface{}) fosite.Session {
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
	return s.UserSession.Clone().(fosite.Session)
}

type AuthorizeCodeWrap struct {
	AuthorizeCodeSession
}

func NewAuthorizeCodeWrap(i interface{}) fosite.Requester {
	return &AuthorizeCodeWrap{i.(AuthorizeCodeSession)}
}

func (ac *AuthorizeCodeWrap) GetID() string {
	return ac.GetID()
}

func (ac *AuthorizeCodeWrap) GetClient() fosite.Client {
	client := ac.AuthorizeCodeSession.GetClient()
	return NewClientWrapper(client)
}

func (ac *AuthorizeCodeWrap) GetGrantedScopes() fosite.Arguments {
	return fosite.Arguments(ac.AuthorizeCodeSession.GetGrantedScopes())
}

func (ac *AuthorizeCodeWrap) GetRequestForm() url.Values {
	return url.Values{}
}

func (ac *AuthorizeCodeWrap) GetRequestedScopes() fosite.Arguments {
	return fosite.Arguments(ac.AuthorizeCodeSession.GetRequestedScopes())
}

func (ac *AuthorizeCodeWrap) SetRequestedScopes(scopes fosite.Arguments) {
	ac.AuthorizeCodeSession.SetRequestedScopes([]string(scopes))
}

func (ac *AuthorizeCodeWrap) GetSession() fosite.Session {
	return NewSessionWrap(ac.AuthorizeCodeSession.GetSession()).(fosite.Session)
}

func (ac *AuthorizeCodeWrap) SetSession(session fosite.Session) {
	ac.AuthorizeCodeSession.SetSession(session)
}

func (ac *AuthorizeCodeWrap) Merge(requester fosite.Requester) {
	ac.AuthorizeCodeSession.Merge(requester)
}

type AccessTokenWrap struct {
	AccessTokenSession
}

func NewAccessTokenWrap(i interface{}) interface{} {
	return &AccessTokenWrap{i.(AccessTokenSession)}
}

func (ac *AccessTokenWrap) GetClient() fosite.Client {
	client := ac.AccessTokenSession.GetClient()
	return NewClientWrapper(client)
}

type RefreshTokenWrap struct {
	RefreshTokenSession
}

func NewRefreshTokenWrap(i interface{}) interface{} {
	return &RefreshTokenWrap{i.(RefreshTokenSession)}
}

func (ac *RefreshTokenWrap) GetClient() fosite.Client {
	client := ac.RefreshTokenSession.GetClient()
	return NewClientWrapper(client)
}
