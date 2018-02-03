/*
 * AuthPlz Application Configuration
 * Defines configuration arguments and environmental variables
 *
 * Copyright 2017 Ryan Kurte
 */

package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"io/ioutil"

	"github.com/jessevdk/go-flags"
	"github.com/ryankurte/go-structparse"
	"gopkg.in/yaml.v2"
)

// CLIOptions defines options that can be passed on the command line
// other options must be passed through the configuration file
type CLIOptions struct {
	ConfigFile string `short:"c" long:"config" description:"AuthPlz configuration file" default:"./authplz.yml"`
	Prefix     string `short:"p" long:"prefix" description:"Prefix for environmental variable loading" default:"AUTHPLZ_"`
}

// AuthPlzConfig configuration structure
type AuthPlzConfig struct {
	Name               string   `yaml:"name"`
	Address            string   `yaml:"bind-address"`
	Port               string   `yaml:"bind-port"`
	ExternalAddress    string   `yaml:"external-address"`
	AllowedOrigins     []string `yaml:"allowed-origins"`
	DisableWebSecurity bool     `yaml:"disable-web-security"`

	Database     string `yaml:"database"`
	CookieSecret string `yaml:"cookie-secret"`
	TokenSecret  string `yaml:"token-secret"`

	StaticDir   string `yaml:"static-dir"`
	TemplateDir string `yaml:"template-dir"`

	TLS    TLSConfig    `yaml:"tls"`
	OAuth  OAuthConfig  `yaml:"oauth"`
	Mailer MailerConfig `yaml:"mailer"`

	MinimumPasswordLength int `yaml:"password-len"`
}

// GenerateSecret Helper to generate a default secret to use
func GenerateSecret(len int) (string, error) {
	data := make([]byte, len)
	n, err := rand.Read(data)
	if err != nil {
		return "", err
	}
	if n != len {
		return "", errors.New("Config: RNG failed")
	}

	return base64.URLEncoding.EncodeToString(data), nil
}

// DefaultConfig Generate default configuration
func DefaultConfig() (*AuthPlzConfig, error) {
	var c AuthPlzConfig
	var err error

	c.Name = "AuthPlz"
	c.Address = "localhost"
	c.Port = "9000"
	c.Database = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Certificate files in environment
	c.TLS.Cert = "server.pem"
	c.TLS.Key = "server.key"
	c.TLS.Disabled = false

	c.StaticDir = "./authplz-ui/build"
	c.TemplateDir = "./templates"

	c.MinimumPasswordLength = 12

	c.Mailer.Driver = "logger"
	c.Mailer.Options = make(map[string]string)

	c.OAuth = DefaultOAuthConfig()

	c.CookieSecret, err = GenerateSecret(64)
	if err != nil {
		return nil, err
	}
	c.TokenSecret, err = GenerateSecret(64)
	if err != nil {
		return nil, err
	}

	return &c, err
}

// LoadConfig loads configuration from the specified file, using the provided prefix for environmental vars
func LoadConfig(filename, envPrefix string) (*AuthPlzConfig, error) {

	c, err := DefaultConfig()
	if err != nil {
		return nil, err
	}

	// Load configuration file
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Parse configuration file
	err = yaml.Unmarshal(data, c)
	if err != nil {
		return nil, err
	}

	// Load specified variables from the environment
	em := structparse.NewEnvironmentMapper("$", envPrefix)
	structparse.Strings(em, c)

	// Load external address if not specified
	if c.ExternalAddress == "" {
		prefix := "https"
		if c.TLS.Disabled {
			prefix = "http"
		}
		c.ExternalAddress = fmt.Sprintf("%s://%s:%s", prefix, c.Address, c.Port)
	}

	// Populate allowed origins with external address if unspecified
	if len(c.AllowedOrigins) == 0 {
		c.AllowedOrigins = []string{c.ExternalAddress}
	}

	// Decode secrets to strings
	tokenSecret, err := base64.URLEncoding.DecodeString(c.TokenSecret)
	if err != nil {
		log.Panicf("Error decoding token secret: %s", err)
	}

	cookieSecret, err := base64.URLEncoding.DecodeString(c.CookieSecret)
	if err != nil {
		log.Panicf("Error decoding cookie secret: %s", err)
	}

	oauthSecret, err := base64.URLEncoding.DecodeString(c.OAuth.TokenSecret)
	if err != nil {
		log.Panicf("Error decoding oauth secret: %s", err)
	}

	c.TokenSecret = string(tokenSecret)
	c.CookieSecret = string(cookieSecret)
	c.OAuth.TokenSecret = string(oauthSecret)

	return c, nil
}

// GetConfig fetches the server configuration
// This parses environmental variables, command line flags, and handles file based loading of configurations.
func GetConfig() (*AuthPlzConfig, error) {

	// Load command line arguments
	cli := CLIOptions{}
	_, err := flags.Parse(&cli)
	if err != nil {
		return nil, err
	}

	return LoadConfig(cli.ConfigFile, cli.Prefix)
}
