/* AuthPlz Authentication and Authorization Microservice
 * Configuration tests
 *
 * Copyright 2018 Ryan Kurte
 */
package config

import (
	"testing"

	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"os"
)

func TestConfig(t *testing.T) {

	testCookieSecret := "TEST_COOKIE_SECRET"
	os.Setenv("AUTHPLZ_COOKIE_SECRET", base64.URLEncoding.EncodeToString([]byte(testCookieSecret)))
	testTokenSecret := "TEST_TOKEN_SECRET"
	os.Setenv("AUTHPLZ_TOKEN_SECRET", base64.URLEncoding.EncodeToString([]byte(testTokenSecret)))

	// GetConfig should load defaults, example config, and infil vars (if set)
	c, err := LoadConfig("../../authplz.yml", "AUTHPLZ_")
	assert.Nil(t, err)

	assert.EqualValues(t, "AuthPlz Example", c.Name)
	assert.EqualValues(t, "localhost", c.Address)
	assert.EqualValues(t, "9000", c.Port)
	//assert.EqualValues(t, "https://localhost:3000", c.ExternalAddress)

	assert.EqualValues(t, testCookieSecret, c.CookieSecret)
	assert.EqualValues(t, testTokenSecret, c.TokenSecret)

}
