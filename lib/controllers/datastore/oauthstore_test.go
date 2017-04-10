package datastore

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ryankurte/authplz/lib/controllers/datastore/oauth2"
)

func TestOauthstore(t *testing.T) {
	// Setup user controller for testing
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"
	//var dbString = "postgres://postgres:postgres@localhost/postgres"

	// Attempt database connection
	ds, err := NewDataStore(dbString)
	if err != nil {
		t.Errorf("%s", err)
		t.FailNow()
	}
	defer ds.Close()

	ds.ForceSync()

	var fakeEmail = "test1@abc.com"
	var fakePass = "abcDEF123@"
	var fakeName = "user.sdfsfdF"

	var user *User

	// Run tests
	t.Run("Add user", func(t *testing.T) {
		// Create user
		u, err := ds.AddUser(fakeEmail, fakeName, fakePass)
		assert.Nil(t, err, "User creation error")
		assert.NotNil(t, u, "No user instance returned")

		u2, err2 := ds.GetUserByEmail(fakeEmail)
		assert.Nil(t, err2, "User fetch error")
		assert.NotNil(t, u2, "No user instance returned")

		user = u2.(*User)

		assert.EqualValues(t, fakeEmail, user.GetEmail())
	})

	t.Run("Check OauthStore is bound", func(t *testing.T) {
		if ds.OauthStore == nil {
			t.Errorf("OAuth store not bound")
		}
	})

	clientId := "oauth-fake-client-id"
	clientSecret := "oauth-fake-secret"

	scopes := []string{"public.read", "public.write", "private.read", "private.write"}
	redirects := []string{"https://fake-redirect.dogs:9000/auth"}
	grants := []string{"client_credentials", "implicit", "authorization_code"}
	responses := []string{"token", "code"}

	var client *oauthstore.OauthClient

	t.Run("Add client", func(t *testing.T) {

		c, err := ds.OauthStore.AddClient(user.ExtID, clientId, clientSecret, scopes, redirects, grants, responses, true)
		assert.Nil(t, err, "Client creation error")
		assert.NotNil(t, c, "No client instance returned")

		client = c.(*oauthstore.OauthClient)

		assert.EqualValues(t, clientId, client.ClientID)
		assert.EqualValues(t, clientSecret, client.Secret)

		assert.EqualValues(t, scopes, client.GetScopes())
		assert.EqualValues(t, redirects, client.GetRedirectURIs())
		assert.EqualValues(t, grants, client.GetGrantTypes())
		assert.EqualValues(t, responses, client.GetResponseTypes())
	})

	fakeAuthorizeCode := "oauth-fake-authorize-code"
	fakeAuthorizeCodeRequestID := "oauth-fake-authorize-request-id"

	t.Run("Add Authorize Code session", func(t *testing.T) {
		acs, err := ds.OauthStore.AddAuthorizeCodeSession(user.ExtID, client.ClientID, fakeAuthorizeCode, fakeAuthorizeCodeRequestID, time.Now(), time.Now().Add(time.Hour*1), scopes, scopes)

		assert.Nil(t, err, "Authorize Code  creation error")
		assert.NotNil(t, acs, "No authorize code instance returned")

		authorizeCodeSession := acs.(*oauthstore.OauthAuthorizeCode)

		c := authorizeCodeSession.GetClient()
		assert.NotNil(t, c, "Could not fetch client for authorize code session")

	})

	t.Run("Fetch Authorize Code session by code", func(t *testing.T) {
		acs, err := ds.OauthStore.GetAuthorizeCodeSession(fakeAuthorizeCode)
		assert.Nil(t, err, "Access Token creation error")
		assert.NotNil(t, acs, "No authorize code instance returned")

		authorizeCodeSession := acs.(*oauthstore.OauthAuthorizeCode)

		c := authorizeCodeSession.GetClient()
		assert.NotNil(t, c, "Could not fetch client for authorize code session")

		client := c.(*oauthstore.OauthClient)
		assert.EqualValues(t, clientId, client.GetID())
	})

	t.Run("Fetch Authorize Code session by request id", func(t *testing.T) {
		ats, err := ds.OauthStore.GetAuthorizeCodeSessionByRequestID(fakeAuthorizeCodeRequestID)
		assert.Nil(t, err, "Authorize code fetch error")
		assert.NotNil(t, ats, "No access token instance returned")

		authorizeCodeSession := ats.(*oauthstore.OauthAuthorizeCode)

		c := authorizeCodeSession.GetClient()
		assert.NotNil(t, c, "Could not fetch client for authorize code session")

		client := c.(*oauthstore.OauthClient)
		assert.EqualValues(t, clientId, client.GetID())
	})

	fakeAccessToken := "oauth-fake-access-token"
	fakeAccessTokenRequestID := "oauth-fake-access-token-request-id"

	t.Run("Add Access Token session", func(t *testing.T) {
		ats, err := ds.OauthStore.AddAccessTokenSession(user.ExtID, client.ClientID, fakeAccessToken, fakeAccessTokenRequestID, time.Now(), time.Now().Add(time.Hour*1), scopes, scopes)

		assert.Nil(t, err, "Access Token creation error")
		assert.NotNil(t, ats, "No access token instance returned")

		accessTokenSession := ats.(*oauthstore.OauthAccessToken)

		c := accessTokenSession.GetClient()
		assert.NotNil(t, c, "Could not fetch client for access token session")
	})

	t.Run("Fetch Access Token session by token", func(t *testing.T) {
		ats, err := ds.OauthStore.GetAccessTokenSession(fakeAccessToken)
		assert.Nil(t, err, "Access Token fetch error")
		assert.NotNil(t, ats, "No access token instance returned")

		accessTokenSession := ats.(*oauthstore.OauthAccessToken)

		c := accessTokenSession.GetClient()
		assert.NotNil(t, c, "Could not fetch client for access token session")

		client := c.(*oauthstore.OauthClient)
		assert.EqualValues(t, clientId, client.GetID())
	})

	t.Run("Fetch Access Token session by request id", func(t *testing.T) {
		ats, err := ds.OauthStore.GetAccessTokenSessionByRequestID(fakeAccessTokenRequestID)
		assert.Nil(t, err, "Access Token fetch error")
		assert.NotNil(t, ats, "No access token instance returned")

		accessTokenSession := ats.(*oauthstore.OauthAccessToken)

		c := accessTokenSession.GetClient()
		assert.NotNil(t, c, "Could not fetch client for access token session")

		client := c.(*oauthstore.OauthClient)
		assert.EqualValues(t, clientId, client.GetID())
	})

	fakeRefreshToken := "oauth-fake-access-token"
	fakeRefreshTokenRequestID := "oauth-fake-access-token-request-id"

	t.Run("Add Refresh Token session", func(t *testing.T) {
		rts, err := ds.OauthStore.AddRefreshTokenSession(user.ExtID, client.ClientID, fakeRefreshToken, fakeRefreshTokenRequestID, time.Now(), time.Now().Add(time.Hour*1), scopes, scopes)

		assert.Nil(t, err, "Refresh Token  creation error")
		assert.NotNil(t, rts, "No refresh token instance returned")

		refreshTokenSession := rts.(*oauthstore.OauthRefreshToken)

		c := refreshTokenSession.GetClient()
		assert.NotNil(t, c, "Could not fetch client for refresh token session")
	})

	t.Run("Fetch Refresh Token session by token", func(t *testing.T) {
		rts, err := ds.OauthStore.GetRefreshTokenBySignature(fakeRefreshToken)
		assert.Nil(t, err, "Refresh Token fetch error")
		assert.NotNil(t, rts, "No refresh token instance returned")

		refreshTokenSession := rts.(*oauthstore.OauthRefreshToken)

		c := refreshTokenSession.GetClient()
		assert.NotNil(t, c, "Could not fetch client for refresh token session")

		client := c.(*oauthstore.OauthClient)
		assert.EqualValues(t, clientId, client.GetID())
	})

	t.Run("Fetch Refresh Token session by request id", func(t *testing.T) {
		rts, err := ds.OauthStore.GetRefreshTokenSessionByRequestID(fakeRefreshTokenRequestID)
		assert.Nil(t, err, "Refresh Token fetch error")
		assert.NotNil(t, rts, "No refresh token instance returned")

		refreshTokenSession := rts.(*oauthstore.OauthRefreshToken)

		c := refreshTokenSession.GetClient()
		assert.NotNil(t, c, "Could not fetch client for refresh token session")

		client := c.(*oauthstore.OauthClient)
		assert.EqualValues(t, clientId, client.GetID())
	})
}
