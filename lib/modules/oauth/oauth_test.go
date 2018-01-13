package oauth

// +build all controller

import (
	"fmt"
	"testing"

	"github.com/authplz/authplz-core/lib/config"
	"github.com/authplz/authplz-core/lib/controllers/datastore"
	"github.com/authplz/authplz-core/lib/test"
)

func NoTestOauth(t *testing.T) {

	ts, err := test.NewTestServer()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	config := config.DefaultOAuthConfig()

	oauthModule := NewController(ts.DataStore, config)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	u, err := ts.DataStore.AddUser(test.FakeEmail, test.FakeName, test.FakePass)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	user := u.(*datastore.User)

	scopes := []string{"public.read", "public.write", "private.read", "private.write"}
	redirects := []string{"https://fake-redirect.cows"}

	grants := []string{"client_credentials"}
	responses := []string{"code", "token"}

	t.Run("Users can create specified grant types", func(t *testing.T) {
		for i, g := range config.AllowedGrants.Admin {
			c, err := oauthModule.CreateClient(user.GetExtID(), fmt.Sprintf("client-test-1.%d", i), scopes, redirects, []string{g}, responses, true)
			if arrayContains(config.AllowedGrants.User, g) && err != nil {
				t.Error(err)
			}
			if !arrayContains(config.AllowedGrants.User, g) && err == nil {
				t.Errorf("Unexpected allowed grant type: %s", g)
			}
			if err == nil {
				oauthModule.RemoveClient(c.ClientID)
			}
		}
	})

	t.Run("Admins can create all grant types", func(t *testing.T) {
		user.SetAdmin(true)
		ts.DataStore.UpdateUser(user)

		for i, g := range config.AllowedGrants.Admin {
			c, err := oauthModule.CreateClient(user.GetExtID(), fmt.Sprintf("client-test-2.%d", i), scopes, redirects, []string{g}, responses, true)
			if err != nil {
				t.Error(err)
			} else if c == nil {
				t.Errorf("Nil client returned")
			}
			oauthModule.RemoveClient(c.ClientID)
		}

		user.SetAdmin(false)
		ts.DataStore.UpdateUser(user)
	})

	t.Run("Users can only create valid scopes", func(t *testing.T) {
		scopes := []string{"FakeScope"}
		c, err := oauthModule.CreateClient(user.GetExtID(), fmt.Sprintf("client-test-3"), scopes, redirects, grants, responses, true)
		if err == nil {
			t.Errorf("Unexpected allowed scope: %s", scopes)
			oauthModule.RemoveClient(c.ClientID)
		}
	})

	t.Run("Client names must be unique", func(t *testing.T) {
		user.SetAdmin(true)
		ts.DataStore.UpdateUser(user)

		_, err := oauthModule.CreateClient(user.GetExtID(), fmt.Sprintf("client-test-4"), scopes, redirects, grants, responses, true)
		if err != nil {
			t.Errorf("Unexpected error %s", err)
		}
		_, err = oauthModule.CreateClient(user.GetExtID(), fmt.Sprintf("client-test-4"), scopes, redirects, grants, responses, true)
		if err == nil {
			t.Errorf("Expected duplicate client error")
		}
		oauthModule.RemoveClient(fmt.Sprintf("client-test-4"))

		user.SetAdmin(false)
		ts.DataStore.UpdateUser(user)
	})

}
