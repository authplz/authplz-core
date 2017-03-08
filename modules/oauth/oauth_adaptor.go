package oauth

import (
	"github.com/ory-am/fosite"
)

type OauthAdaptor struct {
	Storer
}

func NewAdaptor(s Storer) *OauthAdaptor {
	return &OauthAdaptor{s}
}

func (oa *OauthAdaptor) GetClient(id string) (fosite.Client, error) {
	c, err := oa.GetClientById(id)
	if err != nil {
		return nil, err
	}
	return c.(fosite.Client), nil
}
