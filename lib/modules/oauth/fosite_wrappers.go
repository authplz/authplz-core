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

func (s *AuthorizeCodeWrap) GetID() string {
	return s.GetID()
}

func (s *AuthorizeCodeWrap) GetClient() fosite.Client {
	client := s.AuthorizeCodeSession.GetClient()
	return NewClientWrapper(client)
}

func (s *AuthorizeCodeWrap) GetGrantedScopes() fosite.Arguments {
	return fosite.Arguments(s.AuthorizeCodeSession.GetGrantedScopes())
}

func (s *AuthorizeCodeWrap) GetRequestForm() url.Values {
	return url.Values{}
}

func (s *AuthorizeCodeWrap) GetRequestedScopes() fosite.Arguments {
	return fosite.Arguments(s.AuthorizeCodeSession.GetRequestedScopes())
}

func (s *AuthorizeCodeWrap) SetRequestedScopes(scopes fosite.Arguments) {
	s.AuthorizeCodeSession.SetRequestedScopes([]string(scopes))
}

func (s *AuthorizeCodeWrap) GetSession() fosite.Session {
	return NewSessionWrap(s.AuthorizeCodeSession.GetSession()).(fosite.Session)
}

func (s *AuthorizeCodeWrap) SetSession(session fosite.Session) {
	s.AuthorizeCodeSession.SetSession(session)
}

func (s *AuthorizeCodeWrap) Merge(requester fosite.Requester) {
	s.AuthorizeCodeSession.Merge(requester)
}

type AccessTokenWrap struct {
	AccessTokenSession
}

func NewAccessTokenWrap(i interface{}) interface{} {
	return &AccessTokenWrap{i.(AccessTokenSession)}
}

func (s *AccessTokenWrap) GetID() string {
	return s.GetID()
}

func (s *AccessTokenWrap) GetClient() fosite.Client {
	client := s.AccessTokenSession.GetClient()
	return NewClientWrapper(client)
}

func (s *AccessTokenWrap) GetGrantedScopes() fosite.Arguments {
	return fosite.Arguments(s.AccessTokenSession.GetGrantedScopes())
}

func (s *AccessTokenWrap) GetRequestForm() url.Values {
	return url.Values{}
}

func (s *AccessTokenWrap) GetRequestedScopes() fosite.Arguments {
	return fosite.Arguments(s.AccessTokenSession.GetRequestedScopes())
}

func (s *AccessTokenWrap) SetRequestedScopes(scopes fosite.Arguments) {
	s.AccessTokenSession.SetRequestedScopes([]string(scopes))
}

func (s *AccessTokenWrap) GetSession() fosite.Session {
	return NewSessionWrap(s.AccessTokenSession.GetSession()).(fosite.Session)
}

func (s *AccessTokenWrap) SetSession(session fosite.Session) {
	s.AccessTokenSession.SetSession(session)
}

func (s *AccessTokenWrap) Merge(requester fosite.Requester) {
	s.AccessTokenSession.Merge(requester)
}

type RefreshTokenWrap struct {
	RefreshTokenSession
}

func NewRefreshTokenWrap(i interface{}) interface{} {
	return &RefreshTokenWrap{i.(RefreshTokenSession)}
}

func (s *RefreshTokenWrap) GetID() string {
	return s.GetID()
}

func (s *RefreshTokenWrap) GetClient() fosite.Client {
	client := s.RefreshTokenSession.GetClient()
	return NewClientWrapper(client)
}

func (s *RefreshTokenWrap) GetGrantedScopes() fosite.Arguments {
	return fosite.Arguments(s.RefreshTokenSession.GetGrantedScopes())
}

func (s *RefreshTokenWrap) GetRequestForm() url.Values {
	return url.Values{}
}

func (s *RefreshTokenWrap) GetRequestedScopes() fosite.Arguments {
	return fosite.Arguments(s.RefreshTokenSession.GetRequestedScopes())
}

func (s *RefreshTokenWrap) SetRequestedScopes(scopes fosite.Arguments) {
	s.RefreshTokenSession.SetRequestedScopes([]string(scopes))
}

func (s *RefreshTokenWrap) GetSession() fosite.Session {
	return NewSessionWrap(s.RefreshTokenSession.GetSession()).(fosite.Session)
}

func (s *RefreshTokenWrap) SetSession(session fosite.Session) {
	s.RefreshTokenSession.SetSession(session)
}

func (s *RefreshTokenWrap) Merge(requester fosite.Requester) {
	s.RefreshTokenSession.Merge(requester)
}
