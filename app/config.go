package app

import "errors"
import "crypto/rand"

// AuthPlz configuration structure
type AuthPlzConfig struct {
    Address      string
    Port         string
    Database     string
    CookieSecret string
    TokenSecret  string
    TlsCert      string
    TlsKey       string
    NoTls        bool
}


func generateSecret(len int) (string, error) {
    data := make([]byte, len)
    n, err := rand.Read(data)
    if err != nil {
        return "", err
    }
    if n != len {
        return "", errors.New("Config: RNG failed")
    }

    return string(data), nil
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

    var err error

    c.CookieSecret, err = generateSecret(32)
    if err != nil {
        return nil, err
    }
    c.TokenSecret, err = generateSecret(32)
    if err != nil {
        return nil, err
    }

    return &c, nil
}