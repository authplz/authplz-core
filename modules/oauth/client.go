package oauth

import (
	"github.com/ory-am/fosite"
)

// ClientWrapper overrides Client interface with Fosite specific types
type ClientWrapper struct {
	Client
}

// NewClientWrapper creates a client wrapper around a Client interface object
// to support the methods required by Fosite
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
