package oauth

import (
	"github.com/ory-am/fosite"
	"strings"
)

// ClientWrapper overrides Client interface with Fosite specific types
type ClientWrapper struct {
	Client
}

func NewClientWrapper(c interface{}) *ClientWrapper {
	return &ClientWrapper{c.(Client)}
}

func (c *ClientWrapper) GetHashedSecret() []byte {
	return []byte(c.Client.GetSecret())
}

func (c *ClientWrapper) GetRedirectURIs() []string {
	return strings.Split(c.Client.GetRedirectURIs(), ";")
}
func (c *ClientWrapper) GetGrantTypes() fosite.Arguments {
	return strings.Split(c.Client.GetGrants(), ";")
}
func (c *ClientWrapper) GetResponseTypes() fosite.Arguments {
	return strings.Split(c.Client.GetResponseTypes(), ";")
}
func (c *ClientWrapper) GetScopes() fosite.Arguments {
	return strings.Split(c.Client.GetScopes(), ";")
}
