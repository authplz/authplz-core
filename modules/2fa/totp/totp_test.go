package totp

import (
	"testing"
	"time"
)

import (
	"github.com/pquerna/otp"
	totp "github.com/pquerna/otp/totp"
	"github.com/ryankurte/authplz/controllers/datastore"
)

func TestU2FModule(t *testing.T) {
	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@abcDEF123@"
	var fakeName = "user.sdfsfdF"
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Attempt database connection
	dataStore, err := datastore.NewDataStore(dbString)
	if err != nil {
		t.Error("Error opening database")
		t.FailNow()
	}

	// Force synchronization
	dataStore.ForceSync()

	// Create user for tests
	u, err := dataStore.AddUser(fakeEmail, fakeName, fakePass)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	user := u.(*datastore.User)

	var token *otp.Key

	// Instantiate u2f module
	totpModule := NewController("localhost", dataStore)

	t.Run("Create token", func(t *testing.T) {
		to, err := totpModule.CreateToken(user.GetExtId())
		if err != nil {
			t.Error(err)
		}
		if to == nil {
			t.Errorf("Challenge is nil")
		}

		token = to
	})

	t.Run("Register tokens", func(t *testing.T) {
		// Generate response
		code, err := totp.GenerateCode(token.Secret(), time.Now())
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		ok, err := totpModule.ValidateRegistration(user.GetExtId(), "test token", token.Secret(), code)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if !ok {
			t.Errorf("Token registration validation failed")
		}
	})

	t.Run("List tokens", func(t *testing.T) {
		tokens, err := totpModule.ListTokens(user.GetExtId())
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if len(tokens) != 1 {
			t.Errorf("Expected 1 token, receved %d tokens", len(tokens))
		}

	})

	t.Run("Authenticate using a token", func(t *testing.T) {
		code, err := totp.GenerateCode(token.Secret(), time.Now())
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		ok, err := totpModule.ValidateToken(user.GetExtId(), code)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if !ok {
			t.Errorf("Token validation failed")
		}
	})

}
