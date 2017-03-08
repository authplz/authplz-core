package oauth

import "time"

// Oauth client registration
type OauthClient struct {
	UserId        string
	ClientId      string
	CreatedAt     time.Time
	LastUsed      time.Time
	Secret        string
	Scopes        string
	RedirectURI   string
	GrantTypes    string
	ResponseTypes string
	UserData      interface{}
}

func (c OauthClient) GetId() string            { return c.ClientId }
func (c OauthClient) GetSecret() string        { return c.Secret }
func (c OauthClient) GetRedirectUri() string   { return c.RedirectURI }
func (c OauthClient) GetUserData() interface{} { return c.UserData }

func (c OauthClient) SetId(id string)                   { c.ClientId = id }
func (c OauthClient) SetSecret(secret string)           { c.Secret = secret }
func (c OauthClient) SetRedirectURI(redirectURI string) { c.RedirectURI = redirectURI }
func (c OauthClient) SetUserData(userData string)       { c.UserData = userData }

func (c OauthClient) Sanatise() OauthClient {
	return OauthClient{
		UserId:      c.UserId,
		ClientId:    c.ClientId,
		CreatedAt:   c.CreatedAt,
		LastUsed:    c.LastUsed,
		Scopes:      c.Scopes,
		RedirectURI: c.RedirectURI,
		UserData:    c.UserData,
	}
}
