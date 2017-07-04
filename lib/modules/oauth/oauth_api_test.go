/*
 * OAuth Module API Tests
 * Tests the functionality of the OAuth API
 *
 * AuthPlz Project (https://github.com/ryankurte/AuthPlz)
 * Copyright 2017 Ryan Kurte
 */

// +build all api

package oauth

import (
	"fmt"
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

	"github.com/ryankurte/authplz/lib/config"
	"github.com/ryankurte/authplz/lib/controllers/datastore"
	"github.com/ryankurte/authplz/lib/modules/core"
	"github.com/ryankurte/authplz/lib/modules/user"
	"github.com/ryankurte/authplz/lib/test"
)

type OauthError struct {
	Error            string
	ErrorDescription string
}

func GrantOauth(client *test.TestClient, responseType, clientID, redirect string, requestedScopes, grantedScopes []string) (*url.Values, error) {
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
	if err != nil {
		return nil, fmt.Errorf("GrantOauth error: %s", err)
	}
	if err := test.CheckRedirect("/oauth/pending", resp); err != nil {
		return nil, fmt.Errorf("GrantOauth error: %s", err)
	}

	// Fetch pending authorizations
	resp, err = client.Get("/oauth/pending", http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("GrantOauth error: %s", err)
	}
	authReq := fosite.AuthorizeRequest{}
	if err = test.ParseJson(resp, &authReq); err != nil {
		return nil, fmt.Errorf("GrantOauth error: %s", err)
	}
	if authReq.State != v.Get("state") {
		return nil, fmt.Errorf("GrantOauth error: %s", "Invalid state")
	}

	// Accept authorization (post confirm object)
	ac := AuthorizeConfirm{true, v.Get("state"), []string{"public.read"}}
	resp, err = client.PostJSON("/oauth/auth", 302, &ac)
	if err != nil {
		return nil, fmt.Errorf("GrantOauth error: %s", err)
	}

	// Check redirect matches
	redirectResp := resp.Header.Get("Location")
	if !strings.HasPrefix(redirectResp, redirect) {
		return nil, fmt.Errorf("GrantOauth error: Redirect invalid")
	}

	// Parse token args from response
	tokenValues, err := url.ParseQuery(redirect)
	if err != nil {
		return nil, fmt.Errorf("GrantOauth error: %s", err)
	}

	return &tokenValues, nil
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

	client := test.NewTestClient("http://" + test.Address + "/api")

	v := url.Values{}
	v.Set("email", test.FakeEmail)
	v.Set("password", test.FakePass)
	v.Set("username", test.FakeName)

	if _, err := client.PostForm("/create", http.StatusOK, v); err != nil {
		t.Error(err)
		t.FailNow()
	}

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
		if _, err := client.PostForm("/login", http.StatusOK, v); err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Check user status
		if _, err = client.Get("/status", http.StatusOK); err != nil {
			t.Error(err)
			t.FailNow()
		}
	})

	// Run tests
	t.Run("OAuthAPI check API is bound", func(t *testing.T) {
		if _, err := client.Get("/oauth/test", http.StatusOK); err != nil {
			t.Error(err)
		}
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
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if err = test.ParseJson(resp, &oauthClient); err != nil {
			t.Error(err)
			t.FailNow()
		}

		if len(oauthClient.RedirectURIs) != 1 {
			t.Errorf("Error creating oauth client")
			t.FailNow()
		}

		log.Printf("Client: %+v", oauthClient)
	})

	t.Run("OAuthAPI list clients", func(t *testing.T) {
		c, err := oauthModule.GetClients(user.GetExtID())
		if err != nil {
			t.Error(err)
		}

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
		resp, err := client.GetWithParams("/oauth/auth", 302, v)
		if err != nil {
			t.Error(err)
		}
		if err := test.CheckRedirect(config.AuthorizeRedirect, resp); err != nil {
			t.Error(err)
		}

		// Fetch pending authorizations
		resp, err = client.Get("/oauth/pending", http.StatusOK)
		if err != nil {
			t.Error(err)
		}
		authReq := fosite.AuthorizeRequest{}
		if err = test.ParseJson(resp, &authReq); err != nil {
			t.Error(err)
		}
		if authReq.State != v.Get("state") {
			t.Errorf("Invalid state")
		}

		// Accept authorization (post confirm object)
		ac := AuthorizeConfirm{true, v.Get("state"), []string{"public.read"}}
		resp, err = client.PostJSON("/oauth/auth", 302, &ac)
		if err != nil {
			t.Error(err)
		}

		// Check redirect matches
		redirect := resp.Header.Get("Location")
		if !strings.HasPrefix(redirect, oauthClient.RedirectURIs[0]) {
			t.Errorf("Redirect invalid")
		}

		// Parse token args from response
		tokenValues, err := url.ParseQuery(redirect)
		if err != nil {
			t.Error(err)
		}

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

		if _, err := httpClient.Get("http://" + test.Address + "/api/oauth/info"); err != nil {
			t.Errorf("Unexpected error attempting oauth: %s", err)
		}

		// TODO: validate timeouts / scopes / etc.

	})

	t.Run("OAuthAPI Authorization Code grant", func(t *testing.T) {
		v := url.Values{}
		v.Set("response_type", "code")
		v.Set("client_id", oauthClient.ClientID)
		v.Set("redirect_uri", oauthClient.RedirectURIs[0])
		v.Set("scope", "public.read offline")
		v.Set("state", "asf3rjengkrasfdasbtjrb")

		// TODO: solve intermittent database errors
		//t.Skipf("Intermittent errors :-/")

		// Get to start authorization (this is the redirect from the client app)
		resp, err := client.GetWithParams("/oauth/auth", 302, v)
		assert.Nil(t, err)
		assert.Nil(t, test.CheckRedirect(config.AuthorizeRedirect, resp))

		// Fetch pending authorizations
		resp, err = client.Get("/oauth/pending", http.StatusOK)
		assert.Nil(t, err)
		authReq := fosite.AuthorizeRequest{}
		assert.Nil(t, test.ParseJson(resp, &authReq))
		assert.Equal(t, authReq.State, v.Get("state"), "Invalid state")

		// Accept authorization (post confirm object)
		ac := AuthorizeConfirm{true, v.Get("state"), []string{"public.read"}}
		resp, err = client.PostJSON("/oauth/auth", 302, &ac)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

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
				AuthURL:  "http://" + test.Address + "/api/oauth/auth",
				TokenURL: "http://" + test.Address + "/api/oauth/token",
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

		if _, err := httpClient.Get("http://" + test.Address + "/api/oauth/info"); err != nil {
			t.Errorf("Unexpected error attempting oauth: %s", err)
		}

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

		// Get to start authorization (this is the redirect from the client app)
		resp, err := client.GetWithParams("/oauth/auth", 302, v)
		assert.Nil(t, err)
		if err := test.CheckRedirect("/oauth/pending", resp); err != nil {
			t.Error(err)
		}

		// Fetch pending authorizations
		resp, err = client.Get("/oauth/pending", http.StatusOK)
		assert.Nil(t, err)
		authReq := fosite.AuthorizeRequest{}
		if err = test.ParseJson(resp, &authReq); err != nil {
			t.Error(err)
		}
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

		v = url.Values{}
		v.Set("localhost:9000/auth#access_token", tokenValues.Get("localhost:9000/auth#access_token"))

		config := &clientcredentials.Config{
			ClientID:     oauthClient.ClientID,
			ClientSecret: oauthClient.Secret,
			TokenURL:     "http://" + test.Address + "/api/oauth/token",
			Scopes:       []string{"public.read", "private.read"},
		}

		httpClient := config.Client(oauth2.NoContext)

		tc := test.NewTestClientFromHttp("http://"+test.Address+"/api/oauth", httpClient)

		if _, err := tc.Get("/info", http.StatusOK); err != nil {
			t.Error(err)
		}
	})

	t.Run("OAuthAPI lists user sessions", func(t *testing.T) {

		t.SkipNow()

		sessions := UserSessions{}
		if err := client.GetJSON("/oauth/sessions", http.StatusOK, &sessions); err != nil {
			t.Error(err)
			t.FailNow()
		}

		if expected := 2; len(sessions.AccessCodes) != expected {
			t.Errorf("Invalid AccessCodes (explicit, implicit grant) session count (actual: %d expected: %d)", len(sessions.AccessCodes), expected)
		}
		if expected := 0; len(sessions.AuthorizationCodes) != expected {
			t.Errorf("Invalid AuthorizationCodes session count (actual: %d expected: %d)", len(sessions.AuthorizationCodes), expected)
		}
		if expected := 0; len(sessions.RefreshTokens) != expected {
			t.Errorf("Invalid RefreshTokens session count (actual: %d expected: %d)", len(sessions.RefreshTokens), expected)
		}

	})
	/*
		t.Run("OAuthAPI rejects invalid scopes", func(t *testing.T) {
			config := &clientcredentials.Config{
				ClientID:     oauthClient.ClientID,
				ClientSecret: oauthClient.Secret,
				Scopes:       []string{"not-a-scope"},
				TokenURL:     "http://" + test.Address + "/api/oauth/token"}

			httpClient := config.Client(oauth2.NoContext)

			if _, err := httpClient.Get("http://" + test.Address + "/api/oauth/info"); err == nil {
				t.Errorf("Expected error attempting oauth")
			}
		})

		t.Run("OAuthAPI can remove non-interactive clients", func(t *testing.T) {
			if err := oauthModule.RemoveClient(oauthClient.ClientID); err != nil {
				t.Error(err)
			}
		})

		t.Run("Removing non-interactive client causes OAuth to fail", func(t *testing.T) {
			config := &clientcredentials.Config{
				ClientID:     oauthClient.ClientID,
				ClientSecret: oauthClient.Secret,
				TokenURL:     "http://" + test.Address + "/api/oauth/token"}

			httpClient := config.Client(oauth2.NoContext)

			if _, err := httpClient.Get("http://" + test.Address + "/api/oauth/info"); err == nil {
				t.Errorf("Expected error attempting oauth")
			}

		})
	*/
}
