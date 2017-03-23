/*
 * OAuth Module API Tests
 * Tests the functionality of the OAuth API
 *
 * AuthEngine Project (https://github.com/ryankurte/authengine)
 * Copyright 2017 Ryan Kurte
 */

package oauth

import (
	"log"
	"net/http"
	"net/url"
	"testing"

	"github.com/ryankurte/authplz/controllers/datastore"
	"github.com/ryankurte/authplz/test"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type OauthError struct {
	Error            string
	ErrorDescription string
}

func TestOauthAPI(t *testing.T) {

	ts, err := test.NewTestServer()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	config := Config{
		ScopeMatcher:   `^((\/[a-z0-9]+))+$`,
		ScopeValidator: "/u/{{.username}}/",
	}

	// Create and bind oauth server instance
	oauthModule, _ := NewController(ts.DataStore, config)
	oauthModule.BindAPI(ts.Router)

	ts.Run()

	redirect := "localhost:9000/auth"

	var oauthClient *ClientResp

	client := test.NewTestClient("http://" + test.Address + "/api")
	var userID string

	t.Run("Create User", func(t *testing.T) {

		v := url.Values{}
		v.Set("email", test.FakeEmail)
		v.Set("password", test.FakePass)
		v.Set("username", test.FakeName)

		client.BindTest(t).TestPostForm("/create", http.StatusOK, v)

		u, _ := ts.DataStore.GetUserByEmail(test.FakeEmail)

		user := u.(*datastore.User)
		user.SetActivated(true)
		ts.DataStore.UpdateUser(user)

		userID = user.GetExtID()
	})

	t.Run("Login user", func(t *testing.T) {

		// Attempt login
		v := url.Values{}
		v.Set("email", test.FakeEmail)
		v.Set("password", test.FakePass)
		client.BindTest(t).TestPostForm("/login", http.StatusOK, v)

		// Check user status
		client.TestGet("/status", http.StatusOK)
	})

	// Run tests
	t.Run("OAuth check API is bound", func(t *testing.T) {
		client.BindTest(t).TestGet("/oauth/test", http.StatusOK)
	})

	t.Run("OAuth enrol non-interactive client", func(t *testing.T) {
		c, err := oauthModule.CreateClient(userID, "scopeA", redirect, "client_credentials", "token", true)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		oauthClient = c

		log.Printf("OauthClient: %+v", oauthClient)
	})

	t.Run("OAuth list clients", func(t *testing.T) {
		c, err := oauthModule.GetClients(userID)
		if err != nil {
			t.Error(err)
		}
		log.Printf("%+v\n", c)
	})

	t.Run("OAuth login as non-interactive client", func(t *testing.T) {
		config := &clientcredentials.Config{
			ClientID:     oauthClient.ClientID,
			ClientSecret: oauthClient.Secret,
			TokenURL:     "http://" + test.Address + "/api/oauth/token"}

		httpClient := config.Client(oauth2.NoContext)

		tc := test.NewTestClientFromHttp("http://"+test.Address+"/api/oauth", httpClient)

		tc.BindTest(t).TestGet("/info", http.StatusOK)
	})

	t.Run("OAuth can remove non-interactive clients", func(t *testing.T) {
		err := oauthModule.RemoveClient(oauthClient.ClientID)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Removing non-interactive client causes OAuth to fail", func(t *testing.T) {
		config := &clientcredentials.Config{
			ClientID:     oauthClient.ClientID,
			ClientSecret: oauthClient.Secret,
			TokenURL:     "http://" + test.Address + "/api/oauth/token"}

		httpClient := config.Client(oauth2.NoContext)
		_, err := httpClient.Get("http://" + test.Address + "/api/oauth/info")
		if err == nil {
			t.Errorf("Expected error attempting oauth")
		}

	})

	t.Run("OAuth users can register interactive clients", func(t *testing.T) {
		t.Skipf("Unimplemented")
	})

	t.Run("Interactive clients can login with OAuth", func(t *testing.T) {
		t.Skipf("Unimplemented")
	})

}
