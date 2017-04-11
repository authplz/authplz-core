/*
 * AuthPlz Command Line Application Example
 * Demonstrates authentication of command line applications using AuthPlz
 *
 * AuthPlz Project (https://github.com/ryankurte/AuthPlz)
 * Copyright 2017 Ryan Kurte
 */

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"

	//	"golang.org/x/oauth2"

	"github.com/jessevdk/go-flags"
	"time"
)

type Config struct {
	OAuthAddress string `short:"o" long:"oauth-address" description:"Set authorization server endpoint" default:"https://localhost:9000/api/oauth/auth"`
	BindAddress  string `short:"a" long:"bind-address" description:"Set cli bind address" default:"localhost:9002"`
	ClientID     string `short:"i" long:"client-id" description:"Database connection string"`
	ClientSecret string `short:"s" long:"client-secret" default-mask:"-"`
}

func getOAuthLink(c *Config) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", c.ClientID)
	v.Set("redirect_uri", fmt.Sprintf("http://%s", c.BindAddress))
	v.Set("scope", "public.read private.read")
	v.Set("state", "asf3rjengkrasfdasbtjrb")

	return fmt.Sprintf("%s?%s", c.OAuthAddress, v.Encode())
}

func newHandler(ch chan *http.Request) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ch <- r
		w.WriteHeader(http.StatusOK)
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

	// Start local HTTP server (for OAuth redirect)
	ch := make(chan *http.Request)
	http.HandleFunc("/", newHandler(ch))
	go http.ListenAndServe(c.BindAddress, nil)

	// Print auth link for user to click
	link := getOAuthLink(&c)

	fmt.Println("Click the following link to authorize the application")
	fmt.Println(link)

	// Await token from redirect endpoint (with timeout)
	select {
	case resp, ok := <-ch:
		if !ok {
			fmt.Printf("Channel closed error\n")
			break
		}
		fmt.Printf("Received: %+v\n", resp)

	case <-time.After(time.Second * 30):
		fmt.Printf("Timeout awaiting application authorization\n")
	}

	// Save / use token?

}
