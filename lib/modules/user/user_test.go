/*
 * User controller tests
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package user

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/authplz/authplz-core/lib/controllers/datastore"
	"github.com/authplz/authplz-core/lib/events"
	"github.com/authplz/authplz-core/lib/test"
)

func TestUserController(t *testing.T) {
	// Setup user controller for testing
	var fakePass = test.FakePass

	c := test.NewConfig()

	// Attempt database connection
	dataStore, err := datastore.NewDataStore(c.Database)
	if err != nil {
		t.Error("Error opening database")
		t.FailNow()
	}
	dataStore.ForceSync()

	mockEventEmitter := test.MockEventEmitter{}

	// Create controllers
	uc := NewController(dataStore, &mockEventEmitter)

	t.Run("Create user", func(t *testing.T) {
		u, err := uc.Create(test.FakeEmail, test.FakeName, fakePass)
		assert.Nil(t, err)
		if u == nil {
			t.Error("User creation failed")
		}
	})

	t.Run("PreLogin blocks inactivate accounts", func(t *testing.T) {
		u1, _ := uc.userStore.GetUserByEmail(test.FakeEmail)
		res, err := uc.PreLogin(u1)
		assert.Nil(t, err)
		if res {
			t.Error("User login succeeded (and shouldn't have)")
			t.FailNow()
		}
		assert.EqualValues(t, events.AccountNotActivated, mockEventEmitter.Event.Type)
	})

	t.Run("Activate user", func(t *testing.T) {
		u, err := uc.Activate(test.FakeEmail)
		assert.Nil(t, err)
		if u == nil {
			t.Error("No login result")
		}
		assert.EqualValues(t, events.AccountActivated, mockEventEmitter.Event.Type)
	})

	t.Run("Login user", func(t *testing.T) {
		u1, _ := uc.userStore.GetUserByEmail(test.FakeEmail)

		res, _, err := uc.Login(test.FakeEmail, fakePass)
		assert.Nil(t, err)
		if !res {
			t.Error("User login failed")
		}

		res, err = uc.PreLogin(u1)
		assert.Nil(t, err)
		if !res {
			t.Error("User login failed (and shouldn't have)")
			t.FailNow()
		}
	})

	t.Run("PostLoginSuccess hook updates last login time and creates event", func(t *testing.T) {
		u1, _ := uc.userStore.GetUserByEmail(test.FakeEmail)
		assert.Nil(t, err)

		err := uc.PostLoginSuccess(u1)
		assert.Nil(t, err)

		u2, _ := uc.userStore.GetUserByEmail(test.FakeEmail)
		assert.Nil(t, err)

		if u1.(User).GetLastLogin() == u2.(User).GetLastLogin() {
			t.Errorf("Login times match (initial: %v new: %v)", u1.(User).GetLastLogin(), u2.(User).GetLastLogin())
			t.FailNow()
		}

		assert.EqualValues(t, events.LoginSuccess, mockEventEmitter.Event.Type)
	})

	t.Run("Login rejects logins with invalid passwords", func(t *testing.T) {
		res, _, err := uc.Login(test.FakeEmail, "Wrong password")
		if err != nil {
			t.Error(err)
		}
		if res {
			t.Error("User login succeeded with incorrect password")
		}
	})

	t.Run("Login rejects logins with unknown user", func(t *testing.T) {
		res, _, err := uc.Login("not@email.com", fakePass)
		assert.Nil(t, err)
		if res {
			t.Error("User login succeeded with unknown email")
		}
	})

	t.Run("PreLogin rejects disabled user accounts", func(t *testing.T) {
		u, _ := uc.userStore.GetUserByEmail(test.FakeEmail)

		u.(User).SetEnabled(false)
		uc.userStore.UpdateUser(u)

		res, err := uc.PreLogin(u)
		assert.Nil(t, err)
		assert.EqualValues(t, false, res, "User account was not disabled")

		u, _ = uc.userStore.GetUserByEmail(test.FakeEmail)
		u.(User).SetEnabled(true)
		uc.userStore.UpdateUser(u)

		assert.EqualValues(t, events.AccountNotEnabled, mockEventEmitter.Event.Type)
	})

	t.Run("Login locks accounts after N failed attempts", func(t *testing.T) {
		u, _ := uc.userStore.GetUserByEmail(test.FakeEmail)
		if u.(User).IsLocked() {
			t.Errorf("Account already locked")
		}

		for i := 0; i < 6; i++ {
			uc.Login(test.FakeEmail, "Wrong password")
		}

		u, _ = uc.userStore.GetUserByEmail(test.FakeEmail)
		if !u.(User).IsLocked() {
			t.Errorf("Account not locked")
		}
		assert.EqualValues(t, events.AccountLocked, mockEventEmitter.Event.Type)
	})

	t.Run("PreLogin blocks locked accounts", func(t *testing.T) {
		u, _ := uc.userStore.GetUserByEmail(test.FakeEmail)

		res, err := uc.PreLogin(u)
		assert.Nil(t, err)
		assert.EqualValues(t, false, res, "User account was not locked")
		assert.EqualValues(t, events.AccountNotUnlocked, mockEventEmitter.Event.Type)
	})

	t.Run("Unlock unlocks accounts", func(t *testing.T) {
		u, _ := uc.userStore.GetUserByEmail(test.FakeEmail)

		_, err = uc.Unlock(test.FakeEmail)
		assert.Nil(t, err)

		u, _ = uc.userStore.GetUserByEmail(test.FakeEmail)
		if u.(User).IsLocked() {
			t.Errorf("Account is still locked")
		}
		assert.EqualValues(t, events.AccountUnlocked, mockEventEmitter.Event.Type)
	})

	t.Run("Get user", func(t *testing.T) {
		u, err := uc.userStore.GetUserByEmail(test.FakeEmail)
		assert.Nil(t, err)
		assert.NotNil(t, u)

		u1, err := uc.GetUser(u.(User).GetExtID())
		assert.Nil(t, err)
		assert.NotNil(t, u1)
	})

	t.Run("Update user password", func(t *testing.T) {
		u, _ := uc.userStore.GetUserByEmail(test.FakeEmail)

		newPass := test.NewPass

		_, err := uc.UpdatePassword(u.(User).GetExtID(), fakePass, newPass)
		assert.Nil(t, err)

		res, _, err := uc.Login(test.FakeEmail, newPass)
		assert.Nil(t, err)
		assert.EqualValues(t, true, res, "User account login failed")

		fakePass = newPass

		assert.EqualValues(t, events.PasswordUpdate, mockEventEmitter.Event.Type)
	})

	t.Run("Update password updates password changed time", func(t *testing.T) {
		u1, _ := uc.userStore.GetUserByEmail(test.FakeEmail)
		assert.Nil(t, err)

		newPass := "Test new password &$#%"

		_, err := uc.UpdatePassword(u1.(User).GetExtID(), fakePass, newPass)
		assert.Nil(t, err)

		u2, _ := uc.userStore.GetUserByEmail(test.FakeEmail)
		assert.NotNil(t, u2)

		if u1.(User).GetPasswordChanged() == u2.(User).GetPasswordChanged() {
			t.Errorf("Password changed times match (initial: %v new: %v)", u1.(User).GetPasswordChanged(), u2.(User).GetPasswordChanged())
			t.FailNow()
		}
	})

	t.Run("Update password requires correct old password", func(t *testing.T) {

		u, _ := uc.userStore.GetUserByEmail(test.FakeEmail)

		newPass := "Test new password"

		_, err := uc.UpdatePassword(u.(User).GetExtID(), "wrongPass", newPass)
		assert.NotNil(t, err)
	})

	t.Run("PostLoginSuccess causes login success event", func(t *testing.T) {
		u, _ := uc.userStore.GetUserByEmail(test.FakeEmail)

		err := uc.PostLoginSuccess(u)
		assert.Nil(t, err)
		assert.EqualValues(t, events.LoginSuccess, mockEventEmitter.Event.Type)
	})

	t.Run("PostLoginFailure causes login failure event", func(t *testing.T) {
		u, _ := uc.userStore.GetUserByEmail(test.FakeEmail)

		err := uc.PostLoginFailure(u)
		assert.Nil(t, err)
		assert.EqualValues(t, events.LoginFailure, mockEventEmitter.Event.Type)
	})

	// Tear down user controller

}
