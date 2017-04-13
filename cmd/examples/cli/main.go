/*
 * AuthPlz Command Line Application Example
 * Demonstrates authentication of command line applications using AuthPlz
 *
 * AuthPlz Project (https://github.com/ryankurte/AuthPlz)
 * Copyright 2017 Ryan Kurte
 */

package main

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"os"

	//	"golang.org/x/oauth2"

	"github.com/jessevdk/go-flags"
	//"time"
	"encoding/base64"
)

type Config struct {
	OAuthAddress string `short:"o" long:"oauth-address" description:"Set authorization server endpoint" default:"https://localhost:9000/api/oauth/auth"`
	BindAddress  string `short:"a" long:"bind-address" description:"Set cli bind address" default:"localhost:9002"`
	ClientID     string `short:"i" long:"client-id" description:"OAuth2 Client ID"`
	ClientSecret string `short:"s" long:"client-secret" description:"OAuth2 Client Secret" default-mask:"-"`
	TLSCert      string `short:"c" long:"tls-cert" description:"TLS Certificate file" default:"./client.crt"`
	TLSKey       string `short:"k" long:"tls-key" description:"TLS Key file" default:"./client.key"`
}

func getOAuthImplicitLink(c *Config) string {

	b := make([]byte, 32)
	rand.Read(b)

	v := url.Values{}

	v.Set("client_id", c.ClientID)
	v.Set("response_type", "token")
	v.Set("grant_type", "implicit")
	v.Set("redirect_uri", fmt.Sprintf("https://%s", c.BindAddress))
	v.Set("scope", "public.read private.read")
	v.Set("state", base64.StdEncoding.EncodeToString(b))

	return fmt.Sprintf("%s?%s", c.OAuthAddress, v.Encode())
}

func getOauthExplicitLink(c *Config) string {
	b := make([]byte, 32)
	rand.Read(b)

	v := url.Values{}

	v.Set("client_id", c.ClientID)
	v.Set("response_type", "code")
	v.Set("redirect_uri", fmt.Sprintf("https://%s", c.BindAddress))
	v.Set("scope", "public.read private.read")
	v.Set("state", base64.StdEncoding.EncodeToString(b))

	return fmt.Sprintf("%s?%s", c.OAuthAddress, v.Encode())
}

func newHandler(origin string, ch chan *http.Request) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {

		// Set access control to allow auth site queries
		w.Header().Set("access-control-allow-origin", origin)
		w.Header().Set("access-control-allow-credentials", "true")

		err := r.URL.Query().Get("error")
		disc := r.URL.Query().Get("error_description")
		if err != "" {
			fmt.Printf("OAuth error: %s (%s)\n", err, disc)
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusOK)

		fmt.Printf("OAuth response: %+v\n", r.URL.Query())
	}
}

func main() {
	var c Config

	fmt.Println("AuthPlz Command Line Application Example")

	// Load command line args
	_, err := flags.Parse(&c)
	if err != nil {
		os.Exit(-1)
	}

	remote, _ := url.Parse(c.OAuthAddress)
	origin := fmt.Sprintf("%s://%s", remote.Scheme, remote.Host)

	// Start local HTTP server (for OAuth redirect)
	ch := make(chan *http.Request)
	http.HandleFunc("/", newHandler(origin, ch))
	go http.ListenAndServeTLS(c.BindAddress, c.TLSCert, c.TLSKey, nil)

	// Print auth link for user to click
	link := getOauthExplicitLink(&c)

	fmt.Println("Click the following link to authorize the application")
	fmt.Println(link)

	// Await token from redirect endpoint (with timeout)
	for {
		select {
		case resp, ok := <-ch:
			if !ok {
				fmt.Printf("Channel closed error\n")
				break
			}
			fmt.Printf("Received: %+v\n", resp)

			/*
				case <-time.After(time.Second * 30):
					fmt.Printf("Timeout awaiting application authorization\n")
			*/
		}
	}

	// Save / use token?

}
