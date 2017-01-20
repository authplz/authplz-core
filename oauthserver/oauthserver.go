// Implements JWT token building and parsing
// This is used for actions such as user activation, login, account unlock.

package oauthserver

import "github.com/RangelReale/osin"

type OauthServer struct {
	server osin.Server
}

func NewOauthServer() {
	// Create server object
	server := osin.NewServer(osin.NewServerConfig(), &TestStorage{})
}

