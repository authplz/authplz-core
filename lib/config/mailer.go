/* AuthPlz Authentication and Authorization Microservice
 * Mailer configuration
 *
 * Copyright 2018 Ryan Kurte
 */

package config

// MailerConfig Mailer configuration options
type MailerConfig struct {
	Driver  string            `yaml:"driver"`
	Options map[string]string `yaml:"options"`
}
