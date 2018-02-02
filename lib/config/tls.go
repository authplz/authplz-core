/* AuthPlz Authentication and Authorization Microservice
 * TLS Configuration
 *
 * Copyright 2018 Ryan Kurte
 */

package config

// TLSConfig TLS configuration options
type TLSConfig struct {
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	Disabled bool   `yaml:"disabled"`
}
