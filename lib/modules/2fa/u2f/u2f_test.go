/*
 * U2F Tests
 * This defines the interfaces required to use the TOTP module
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package u2f

import (
	"testing"

	"github.com/authplz/authplz-core/lib/config"
	"github.com/authplz/authplz-core/lib/controllers/datastore"
	"github.com/authplz/authplz-core/lib/test"

	"github.com/ryankurte/go-u2f"
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

	// Create virtual key for testing
	vt, _ := u2f.NewVirtualKey()
	mockEventEmitter := test.MockEventEmitter{}

	// Instantiate u2f module
	u2fModule := NewController("localhost", dataStore, &mockEventEmitter)

	t.Run("Create challenges", func(t *testing.T) {
		c, err := u2fModule.GetChallenge(user.GetExtID())
		if err != nil {
			t.Error(err)
		}
		if c == nil {
			t.Errorf("Challenge is nil")
		}
	})

	t.Run("Register tokens", func(t *testing.T) {
		challenge, err := u2fModule.GetChallenge(user.GetExtID())
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		rr := challenge.RegisterRequest()

		resp, err := vt.HandleRegisterRequest(*rr)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		ok, err := u2fModule.ValidateRegistration(user.GetExtID(), "test token", challenge, resp)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if !ok {
			t.Errorf("Token registration validation failed")
		}
	})

	t.Run("List tokens", func(t *testing.T) {
		tokens, err := u2fModule.ListTokens(user.GetExtID())
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if len(tokens) != 1 {
			t.Errorf("Expected 1 token, receved %d tokens", len(tokens))
		}

	})

	t.Run("Authenticate using a token", func(t *testing.T) {
		challenge, err := u2fModule.GetChallenge(user.GetExtID())
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		rr := challenge.SignRequest()

		resp, err := vt.HandleAuthenticationRequest(*rr)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		ok, err := u2fModule.ValidateSignature(user.GetExtID(), challenge, resp)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if !ok {
			t.Errorf("Token signature validation failed")
		}
	})

}
