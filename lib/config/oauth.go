/* AuthPlz Authentication and Authorization Microservice
 * OAuth configuration
 *
 * Copyright 2018 Ryan Kurte
 */

package config

import (
	"time"
)

type configSplit struct {
	Admin []string
	User  []string
}

// OAuthConfig OAuth controller configuration structure
type OAuthConfig struct {
	// Redirect to client app for oauth authorization
	AuthorizeRedirect string
	// Secret for OAuth token attestation
	TokenSecret string
	// AllowedScopes defines the scopes a client can grant for admins and users
	AllowedScopes configSplit
	// AllowedGrants defines the grant types a client can support for admins and users
	AllowedGrants configSplit
	// AllowedResponses defines response types a client can support
	AllowedResponses []string
	// AccessExpiry is Access Token expiry time
	AccessExpiry time.Duration
	// IDExpiry is ID Token expiry time
	IDExpiry time.Duration
	// AuthorizeExpiry is Authorization token expiry time
	AuthorizeExpiry time.Duration
	// RefreshExpiry is Refresh token expiry time
	RefreshExpiry time.Duration
}

// DefaultOAuthConfig generates a default configuration for the OAuth module
func DefaultOAuthConfig() OAuthConfig {
	secret, _ := GenerateSecret(64)
	return OAuthConfig{
		AuthorizeRedirect: "/#/oauth-authorize",
		TokenSecret:       secret,
		AllowedScopes: configSplit{
			Admin: []string{"public.read", "public.write", "private.read", "private.write", "introspect", "offline"},
			User:  []string{"public.read", "public.write", "private.read", "private.write", "offline"},
		},
		AllowedGrants: configSplit{
			Admin: []string{"authorization_code", "implicit", "refresh_token", "client_credentials"},
			User:  []string{"authorization_code", "implicit", "refresh_token"},
		},
		AllowedResponses: []string{"code", "token", "id_token"},
		AccessExpiry:     time.Hour * 24 * 1,
		IDExpiry:         time.Hour * 24 * 1,
		AuthorizeExpiry:  time.Hour * 24 * 1,
		RefreshExpiry:    time.Hour * 24 * 180,
	}
}
