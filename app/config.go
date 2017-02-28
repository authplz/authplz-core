package app

import (
    "log"
    "errors"
    "crypto/rand"
    "encoding/base64"
)

import(
    "github.com/kelseyhightower/envconfig"
    "github.com/jessevdk/go-flags"
)

// AuthPlz configuration structure
type AuthPlzConfig struct {
    Address               string `short:"a" long:"address" description:"Set server address"`
    Port                  string `short:"p" long:"port" description:"Set server port"`
    Database              string `short:"d" long:"database" description:"Database connection string"`
    CookieSecret          string `long:"cookie-secret" description:"32-byte base64 encoded secret for cookie / session storage" default-mask:"-"`
    TokenSecret           string `long:"token-secret" description:"32-byte base64 encoded secret for token use" default-mask:"-"`
    TlsCert               string `short:"c" long:"tls-cert" description:"TLS Certificate file"`
    TlsKey                string `short:"k" long:"tls-key" description:"TLS Key File"`
    NoTls                 bool   `long:"disable-tls" description:"Disable TLS for testing or reverse proxying"`
    StaticDir             string `short:"s" long:"static-dir" description:"Directory to load static assets from"`
    TemplateDir           string `short:"t" long:"template-dir" description:"Directory to load templates from"`
    MinimumPasswordLength int
}

// Helper to generate a default secret to use
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

// Generate default configuration
func DefaultConfig() (*AuthPlzConfig, error) {
    var c AuthPlzConfig

    c.Address = "localhost"
    c.Port = "9000"
    c.Database = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

    // Certificate files in environment
    c.TlsCert = "server.pem"
    c.TlsKey = "server.key"
    c.NoTls = false
    c.StaticDir = "../authplz-ui"
    c.TemplateDir = "./templates"

    c.MinimumPasswordLength = 12

    var err error

    c.CookieSecret, err = GenerateSecret(32)
    if err != nil {
        return nil, err
    }
    c.TokenSecret, err = GenerateSecret(32)
    if err != nil {
        return nil, err
    }

    return &c, nil
}

func GetConfig() *AuthPlzConfig {
    // Fetch default configuration
    c, err := DefaultConfig()
    if err != nil {
        log.Fatal(err.Error())
    }

    // Parse config structure through environment
    err = envconfig.Process("authplz", c)
    if err != nil {
        log.Fatal(err.Error())
    }

    // Override environment with command line args
    _, err = flags.Parse(c)
    if err != nil {
        log.Fatal(err.Error())
    }

    return c
}
