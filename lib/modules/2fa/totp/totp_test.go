package totp

import (
	"testing"
	"time"

	"github.com/ryankurte/authplz/lib/config"
	"github.com/ryankurte/authplz/lib/controllers/datastore"
	"github.com/ryankurte/authplz/lib/test"

	"github.com/pquerna/otp"
	totp "github.com/pquerna/otp/totp"
)

func TestU2FModule(t *testing.T) {
	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@abcDEF123@"
	var fakeName = "user.sdfsfdF"

	c, _ := config.DefaultConfig()

	// Attempt database connection
	dataStore, err := datastore.NewDataStore(c.Database)
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
	mockEventEmitter := test.MockEventEmitter{}

	// Instantiate u2f module
	totpModule := NewController("localhost", dataStore, &mockEventEmitter)

	t.Run("Create token", func(t *testing.T) {
		to, err := totpModule.CreateToken(user.GetExtID())
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

		ok, err := totpModule.ValidateRegistration(user.GetExtID(), "test token", token.Secret(), code)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if !ok {
			t.Errorf("Token registration validation failed")
		}
	})

	t.Run("List tokens", func(t *testing.T) {
		tokens, err := totpModule.ListTokens(user.GetExtID())
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

		ok, err := totpModule.ValidateToken(user.GetExtID(), code)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if !ok {
			t.Errorf("Token validation failed")
		}
	})

}
