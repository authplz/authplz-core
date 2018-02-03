/*
 * OAuth Module API Tests
 * Tests the functionality of the OAuth API
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

// +build all api

package oauth

import (
	"log"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	//"github.com/dghubble/oauth1"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"

	"github.com/authplz/authplz-core/lib/config"
	"github.com/authplz/authplz-core/lib/controllers/datastore"
	"github.com/authplz/authplz-core/lib/modules/core"
	"github.com/authplz/authplz-core/lib/modules/user"
	"github.com/authplz/authplz-core/lib/test"
)

type OauthError struct {
	Error            string
	ErrorDescription string
}

func GrantOauth(client *test.Client, t *testing.T, responseType, clientID, redirect string, requestedScopes, grantedScopes []string) {
	// Build request object
	v := url.Values{}
	v.Set("response_type", responseType)
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirect)
	v.Set("scope", strings.Join(requestedScopes, " "))

	state, _ := generateSecret(32)
	v.Set("state", state)

	// Get to start authorization (this is the redirect from the client app)
	resp, err := client.GetWithParams("/oauth/auth", 302, v)
	assert.Nil(t, err)

	err = test.CheckRedirect("/oauth/pending", resp)
	assert.Nil(t, err)

	// Fetch pending authorizations
	resp, err = client.Get("/oauth/pending", http.StatusOK)
	assert.Nil(t, err)

	authReq := fosite.AuthorizeRequest{}
	err = test.ParseJson(resp, &authReq)
	assert.Nil(t, err)
	assert.EqualValues(t, v.Get("state"), authReq.State)

	// Accept authorization (post confirm object)
	ac := AuthorizeConfirm{true, v.Get("state"), []string{"public.read"}}
	resp, err = client.PostJSON("/oauth/auth", 302, &ac)
	assert.Nil(t, err)

	// Check redirect matches
	redirectResp := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(redirectResp, redirect))

	// Parse token args from response
	tokenValues, err := url.ParseQuery(redirect)
	assert.Nil(t, err)
	log.Printf("TokenValues: %+s", tokenValues)
}

func TestOauthAPI(t *testing.T) {

	ts, err := test.NewTestServer()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	config := config.DefaultOAuthConfig()

	userModule := user.NewController(ts.DataStore, ts.EventEmitter)

	coreModule := core.NewController(ts.TokenControl, userModule, &test.MockEventEmitter{})
	coreModule.BindModule("user", userModule)
	coreModule.BindAPI(ts.Router)
	userModule.BindAPI(ts.Router)

	// Create and bind oauth server instance
	oauthModule := NewController(ts.DataStore, config)
	oauthModule.BindAPI(ts.Router)

	ts.Run()

	redirect := "localhost:9000/auth"

	var oauthClient ClientResp

	client := test.NewClient("http://" + ts.Address() + "/api")

	v := url.Values{}
	v.Set("email", test.FakeEmail)
	v.Set("password", test.FakePass)
	v.Set("username", test.FakeName)

	_, err = client.PostForm("/create", http.StatusOK, v)
	assert.Nil(t, err)

	u, _ := ts.DataStore.GetUserByEmail(test.FakeEmail)

	// Activate user and create admin credentals
	user := u.(*datastore.User)
	user.SetActivated(true)
	user.SetAdmin(true)
	ts.DataStore.UpdateUser(user)

	t.Run("Login user", func(t *testing.T) {
		v := url.Values{}
		v.Set("email", test.FakeEmail)
		v.Set("password", test.FakePass)

		// Attempt login
		_, err := client.PostForm("/login", http.StatusOK, v)
		assert.Nil(t, err)

		// Check user status
		_, err = client.Get("/status", http.StatusOK)
		assert.Nil(t, err)
	})

	scopes := []string{"public.read", "public.write", "private.read", "private.write", "offline", "introspect"}
	redirects := []string{redirect}
	grants := []string{"authorization_code", "implicit", "client_credentials", "refresh_token"}
	responses := []string{"token", "code"}

	t.Run("OAuthAPI create client", func(t *testing.T) {
		cr := ClientReq{
			Name:      "test-client",
			Scopes:    scopes,
			Redirects: redirects,
			Grants:    grants,
			Responses: responses,
		}

		resp, err := client.PostJSON("/oauth/clients", 200, &cr)
		assert.Nil(t, err)
		err = test.ParseJson(resp, &oauthClient)
		assert.Nil(t, err)
		assert.Len(t, oauthClient.RedirectURIs, 1)

		log.Printf("Client: %+v", oauthClient)
	})

	t.Run("OAuthAPI list clients", func(t *testing.T) {
		c, err := oauthModule.GetClients(user.GetExtID())
		assert.Nil(t, err)

		if len(c) != 1 {
			t.Errorf("Invalid client count (actual: %d expected: %d)", len(c), 1)
		}
	})

	// Implicit flow for browser based tokens (no secret storage)
	t.Run("OAuthAPI implicit grant", func(t *testing.T) {
		v := url.Values{}
		v.Set("response_type", "token")
		v.Set("grant_type", "implicit")
		v.Set("client_id", oauthClient.ClientID)
		v.Set("redirect_uri", oauthClient.RedirectURIs[0])
		v.Set("scope", "public.read")
		v.Set("state", "afrjkbhreiulqyaf3q974")

		// Get to start authorization (this is the redirect from the client app)
		resp, err := client.GetWithParams("/oauth/auth", http.StatusOK, v)
		assert.Nil(t, err)

		// Fetch pending authorizations
		resp, err = client.Get("/oauth/pending", http.StatusOK)
		assert.Nil(t, err)

		authReq := fosite.AuthorizeRequest{}
		err = test.ParseJson(resp, &authReq)
		assert.Nil(t, err)
		if authReq.State != v.Get("state") {
			t.Errorf("Invalid state")
		}

		// Accept authorization (post confirm object)
		ac := AuthorizeConfirm{true, v.Get("state"), []string{"public.read"}}
		resp, err = client.PostJSON("/oauth/auth", 302, &ac)
		assert.Nil(t, err)

		// Check redirect matches
		redirect := resp.Header.Get("Location")
		if !strings.HasPrefix(redirect, oauthClient.RedirectURIs[0]) {
			t.Errorf("Redirect invalid")
		}

		// Parse token args from response
		tokenValues, err := url.ParseQuery(redirect)
		assert.Nil(t, err)

		if err := tokenValues.Get(oauthClient.RedirectURIs[0] + "?error"); err != "" {
			t.Errorf("Error from auth endpoint %s", err)
			t.FailNow()
		}

		tokenString := tokenValues.Get(oauthClient.RedirectURIs[0] + "#access_token")
		if tokenString == "" {
			t.Errorf("No access token received")
			t.FailNow()
		}

		// Test token
		config := &oauth2.Config{}
		token := &oauth2.Token{AccessToken: tokenString}
		httpClient := config.Client(oauth2.NoContext, token)

		_, err = httpClient.Get("http://" + ts.Address() + "/api/oauth/info")
		assert.Nil(t, err)

		// TODO: validate timeouts / scopes / etc.

	})

	t.Run("OAuthAPI Authorization Code grant", func(t *testing.T) {
		v := url.Values{}
		v.Set("response_type", "code")
		v.Set("client_id", oauthClient.ClientID)
		v.Set("redirect_uri", oauthClient.RedirectURIs[0])
		v.Set("scope", "public.read offline")
		v.Set("state", "asf3rjengkrasfdasbtjrb")

		// Get to start authorization (this is the redirect from the client app)
		resp, err := client.GetWithParams("/oauth/auth", http.StatusOK, v)
		assert.Nil(t, err)

		// Fetch pending authorizations
		resp, err = client.Get("/oauth/pending", http.StatusOK)
		assert.Nil(t, err)
		authReq := fosite.AuthorizeRequest{}
		assert.Nil(t, test.ParseJson(resp, &authReq))
		assert.Equal(t, authReq.State, v.Get("state"), "Invalid state")

		// Accept authorization (post confirm object)
		ac := AuthorizeConfirm{true, v.Get("state"), []string{"public.read"}}
		resp, err = client.PostJSON("/oauth/auth", 302, &ac)
		assert.Nil(t, err)

		// Check redirect matches
		redirect := resp.Header.Get("Location")
		if !strings.HasPrefix(redirect, oauthClient.RedirectURIs[0]) {
			t.Errorf("Redirect invalid")
		}

		// Parse token args from response
		tokenValues, err := url.ParseQuery(redirect)
		assert.Nil(t, err)

		if err := tokenValues.Get(oauthClient.RedirectURIs[0] + "?error"); err != "" {
			t.Errorf("Error from auth endpoint %s", err)
			t.FailNow()
		}

		codeString := tokenValues.Get(oauthClient.RedirectURIs[0] + "?code")
		if codeString == "" {
			t.Errorf("No authorization code received")
			t.FailNow()
		}

		// Setup OAuth client
		config := &oauth2.Config{
			ClientID:     oauthClient.ClientID,
			ClientSecret: oauthClient.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "http://" + ts.Address() + "/api/oauth/auth",
				TokenURL: "http://" + ts.Address() + "/api/oauth/token",
			},
			RedirectURL: oauthClient.RedirectURIs[0],
			Scopes:      oauthClient.Scopes,
		}

		log.Printf("Authorization Code Config: %+v", config)

		// Swap access code for token
		accessToken, err := config.Exchange(oauth2.NoContext, codeString)
		if err != nil {
			t.Errorf("Error swapping code for token: %s", err)
		}

		httpClient := config.Client(oauth2.NoContext, accessToken)

		_, err = httpClient.Get("http://" + ts.Address() + "/api/oauth/info")
		assert.Nil(t, err)
	})

	//
	t.Run("OAuthAPI Client Credentials grant", func(t *testing.T) {
		v := url.Values{}
		v.Set("response_type", "token")
		v.Set("client_id", oauthClient.ClientID)
		v.Set("redirect_uri", oauthClient.RedirectURIs[0])
		v.Set("grant_types", "client_credentials")
		v.Set("scope", "introspect")
		v.Set("state", "afrjkbhreiulqyaf3q974")

		t.Skipf("Not currently supported")

		log.Printf("Start OAuth Client Credential request...")

		// Get to start authorization (this is the redirect from the client app)
		resp, err := client.GetWithParams("/oauth/auth", http.StatusOK, v)
		assert.Nil(t, err)

		log.Printf("Fetch pending...")

		// Fetch pending authorizations
		resp, err = client.Get("/oauth/pending", http.StatusOK)
		assert.Nil(t, err)

		authReq := fosite.AuthorizeRequest{}
		err = test.ParseJson(resp, &authReq)
		assert.Nil(t, err)

		if authReq.State != v.Get("state") {
			t.Errorf("Invalid state")
		}

		log.Printf("Authorize Confirm...")

		// Accept authorization (post confirm object)
		ac := AuthorizeConfirm{true, v.Get("state"), []string{"introspect"}}
		resp, err = client.PostJSON("/oauth/auth", http.StatusFound, &ac)
		assert.Nil(t, err)

		// Check redirect matches
		redirect := resp.Header.Get("Location")
		if !strings.HasPrefix(redirect, oauthClient.RedirectURIs[0]) {
			t.Errorf("Redirect invalid")
		}
		log.Printf("Token: %+v", redirect[0])

		// Parse token args from response
		tokenValues, err := url.ParseQuery(redirect)
		assert.Nil(t, err)

		log.Printf("TokenValues: %+v", tokenValues)

		v = url.Values{}
		token := tokenValues.Get("localhost:9000/auth#access_token")
		v.Set("localhost:9000/auth#access_token", token)

		config := &clientcredentials.Config{
			ClientID:     oauthClient.ClientID,
			ClientSecret: oauthClient.Secret,
			TokenURL:     "http://" + ts.Address() + "/api/oauth/token",
			Scopes:       []string{"introspect"},
		}

		httpClient := config.Client(oauth2.NoContext)

		tc := test.NewClientFromHttp("http://"+ts.Address()+"/api/oauth", httpClient)

		_, err = tc.Get("/info", http.StatusOK)
		assert.Nil(t, err)
	})

	t.Run("OAuthAPI lists user sessions", func(t *testing.T) {

		sessions := UserSessions{}
		err := client.GetJSON("/oauth/sessions", http.StatusOK, &sessions)
		assert.Nil(t, err)

		assert.Len(t, sessions.AccessCodes, 2)
		assert.Len(t, sessions.AuthorizationCodes, 0)
		assert.Len(t, sessions.RefreshTokens, 0)

	})

	t.Run("OAuthAPI rejects invalid scopes", func(t *testing.T) {
		config := &clientcredentials.Config{
			ClientID:     oauthClient.ClientID,
			ClientSecret: oauthClient.Secret,
			Scopes:       []string{"not-a-scope"},
			TokenURL:     "http://" + ts.Address() + "/api/oauth/token"}

		httpClient := config.Client(oauth2.NoContext)

		if _, err := httpClient.Get("http://" + ts.Address() + "/api/oauth/info"); err == nil {
			t.Errorf("Expected error attempting oauth")
		}
	})

	t.Run("OAuthAPI can remove non-interactive clients", func(t *testing.T) {
		err := oauthModule.RemoveClient(oauthClient.ClientID)
		assert.Nil(t, err)
	})

	t.Run("Removing non-interactive client causes OAuth to fail", func(t *testing.T) {
		t.SkipNow()
		config := &clientcredentials.Config{
			ClientID:     oauthClient.ClientID,
			ClientSecret: oauthClient.Secret,
			TokenURL:     "http://" + ts.Address() + "/api/oauth/token"}

		httpClient := config.Client(oauth2.NoContext)

		if _, err := httpClient.Get("http://" + ts.Address() + "/api/oauth/info"); err == nil {
			t.Errorf("Expected error attempting oauth")
		}

	})
}
