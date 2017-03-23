package oauth

import (
	"github.com/ryankurte/authplz/test"
	"testing"
)

func TestOauth(t *testing.T) {

	ts, err := test.NewTestServer()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	config := Config{
		ScopeMatcher:   `^((\/[a-z0-9_]+))+$`,
		ScopeValidator: "/u/{{.username}}/",
	}

	oauthModule, err := NewController(ts.DataStore, config)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Run("Validates scopes", func(t *testing.T) {

		testScopes := []string{"/u/testuser"}
		if scopes := oauthModule.ValidateScopes("testuser", testScopes); len(scopes) != 1 {
			t.Errorf("Scope %s validaton failed", testScopes[0])
		}

		testScopes = []string{"/u/fakeuser"}
		if scopes := oauthModule.ValidateScopes("testuser", testScopes); len(scopes) != 0 {
			t.Errorf("Scope %s validaton passed (expected failure due to username mismatch)", testScopes[0])
		}

		testScopes = []string{"/u/testuser/*"}
		if scopes := oauthModule.ValidateScopes("testuser", testScopes); len(scopes) != 0 {
			t.Errorf("Scope %s validaton passed (expected failure due to invalid characters)", testScopes[0])
		}

		testScopes = []string{"/"}
		if scopes := oauthModule.ValidateScopes("testuser", testScopes); len(scopes) != 0 {
			t.Errorf("Scope %s validaton passed (expected failure due to invalid path)", testScopes[0])
		}

	})

}
