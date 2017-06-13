package config

type OauthClientPermission struct {
	Scopes []string `yaml:"scopes"`
	Grants []string `yaml:"grants"`
}

// OauthConfig OAuth controller configuration structure
type OauthConfig struct {
	// Secret for OAuth token attestation
	Secret string `yaml:"secret"`

	// Admin oauth client options
	Admin OauthClientPermission `yaml:"admin"`

	// User oauth client options
	User OauthClientPermission `yaml:"user"`

	// AllowedResponses defines response types a client can support
	AllowedResponses []string `yaml:"allowed-responses"`
}
