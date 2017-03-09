package oauth

import (
	"github.com/ory-am/fosite"
)

// OauthAdaptor adapts a generic interface for Fosite compliance
type OauthAdaptor struct {
	Storer
}

func NewAdaptor(s Storer) *OauthAdaptor {
	return &OauthAdaptor{s}
}

// Get an OAuth client by ClientID
func (oa *OauthAdaptor) GetClient(id string) (fosite.Client, error) {
	c, err := oa.GetClientByID(id)
	if err != nil {
		return nil, err
	}
	return c.(fosite.Client), nil
}

func (oa *OauthAdaptor) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error) {

}
