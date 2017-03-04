package oauth

import (
	"github.com/ryankurte/authplz/api"
)

type OauthModule struct {
}

// Create a new core module instance
func NewOauthModule() *OauthModule {
	return &OauthModule{}
}

// Handle tokens if required
func (oauthModule *OauthModule) HandleToken(u interface{}, action api.TokenAction) (err error) {
	return nil
}
