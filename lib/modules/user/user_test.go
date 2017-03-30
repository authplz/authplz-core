package user

import "testing"

import (
	"github.com/ryankurte/authplz/lib/controllers/datastore"
	"github.com/ryankurte/authplz/lib/test"
)

func TestUserController(t *testing.T) {
	// Setup user controller for testing
	var fakeEmail = "test@abc.com"
	var fakeName = "test.user"
	var fakePass = "abcDEF123@abcDEF123@"
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Attempt database connection
	dataStore, err := datastore.NewDataStore(dbString)
	if err != nil {
		t.Error("Error opening database")
		t.FailNow()
	}
	dataStore.ForceSync()

	mockEventEmitter := test.MockEventEmitter{}

	// Create controllers
	uc := NewController(dataStore, &mockEventEmitter)

	t.Run("Create user", func(t *testing.T) {
		u, err := uc.Create(fakeEmail, fakeName, fakePass)
		if err != nil {
			t.Error(err)
		}
		if u == nil {
			t.Error("User creation failed")
		}
	})

	t.Run("PreLogin blocks inactivate accounts", func(t *testing.T) {
		u1, _ := uc.userStore.GetUserByEmail(fakeEmail)
		res, err := uc.PreLogin(u1)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if res {
			t.Error("User login succeeded (and shouldn't have)")
			t.FailNow()
		}
	})

	t.Run("Activate user", func(t *testing.T) {
		u, err := uc.Activate(fakeEmail)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if u == nil {
			t.Error("No login result")
		}
	})

	t.Run("Login user", func(t *testing.T) {
		u1, _ := uc.userStore.GetUserByEmail(fakeEmail)

		res, _, err := uc.Login(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
		}
		if !res {
			t.Error("User login failed")
		}

		res, err = uc.PreLogin(u1)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if !res {
			t.Error("User login failed (and shouldn't have)")
			t.FailNow()
		}
	})

	t.Run("PostLoginSuccess hook updates last login time", func(t *testing.T) {
		u1, _ := uc.userStore.GetUserByEmail(fakeEmail)
		if u1 == nil {
			t.Error("No user found")
			t.FailNow()
		}

		err := uc.PostLoginSuccess(u1)
		if err != nil {
			t.Error(err)
		}

		u2, _ := uc.userStore.GetUserByEmail(fakeEmail)
		if u2 == nil {
			t.Error("No user found")
			t.FailNow()
		}

		if u1.(User).GetLastLogin() == u2.(User).GetLastLogin() {
			t.Errorf("Login times match (initial: %v new: %v)", u1.(User).GetLastLogin(), u2.(User).GetLastLogin())
			t.FailNow()
		}
	})

	t.Run("Login rejects logins with invalid passwords", func(t *testing.T) {
		res, _, err := uc.Login(fakeEmail, "Wrong password")
		if err != nil {
			t.Error(err)
		}
		if res {
			t.Error("User login succeeded with incorrect password")
		}
	})

	t.Run("Login rejects logins with unknown user", func(t *testing.T) {
		res, _, err := uc.Login("not@email.com", fakePass)
		if err != nil {
			t.Error(err)
		}
		if res {
			t.Error("User login succeeded with unknown email")
		}
	})

	t.Run("PreLogin rejects disabled user accounts", func(t *testing.T) {
		u, _ := uc.userStore.GetUserByEmail(fakeEmail)

		u.(User).SetEnabled(false)
		uc.userStore.UpdateUser(u)

		res, err := uc.PreLogin(u)
		if err != nil {
			t.Error(err)
		}
		if res {
			t.Error("User login succeeded with account disabled")
		}

		u, _ = uc.userStore.GetUserByEmail(fakeEmail)
		u.(User).SetEnabled(true)
		uc.userStore.UpdateUser(u)
	})

	t.Run("Login locks accounts after N failed attempts", func(t *testing.T) {
		u, _ := uc.userStore.GetUserByEmail(fakeEmail)
		if u.(User).IsLocked() {
			t.Errorf("Account already locked")
		}

		for i := 0; i < 6; i++ {
			uc.Login(fakeEmail, "Wrong password")
		}

		u, _ = uc.userStore.GetUserByEmail(fakeEmail)
		if !u.(User).IsLocked() {
			t.Errorf("Account not locked")
		}
	})

	t.Run("PreLogin blocks locked accounts", func(t *testing.T) {
		u, _ := uc.userStore.GetUserByEmail(fakeEmail)

		res, err := uc.PreLogin(u)
		if err != nil {
			t.Error(err)
		}
		if res {
			t.Error("User account was not locked", res)
		}
	})

	t.Run("Unlock unlocks accounts", func(t *testing.T) {
		u, _ := uc.userStore.GetUserByEmail(fakeEmail)

		_, err = uc.Unlock(fakeEmail)
		if err != nil {
			t.Error(err)
		}

		u, _ = uc.userStore.GetUserByEmail(fakeEmail)
		if u.(User).IsLocked() {
			t.Errorf("Account is still locked")
		}
	})

	t.Run("Get user", func(t *testing.T) {

		u, _ := uc.userStore.GetUserByEmail(fakeEmail)
		if u == nil {
			t.Error("No user found")
			t.FailNow()
		}

		u1, err := uc.GetUser(u.(User).GetExtID())
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if u1 == nil {
			t.Error("No user fetched")
		}

	})

	t.Run("Update user password", func(t *testing.T) {
		u, _ := uc.userStore.GetUserByEmail(fakeEmail)

		newPass := "Test new password"

		_, err := uc.UpdatePassword(u.(User).GetExtID(), fakePass, newPass)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		res, _, err := uc.Login(fakeEmail, newPass)
		if err != nil {
			t.Error(err)
		}
		if !res {
			t.Error("User account login failed", res)
		}

		fakePass = newPass
	})

	t.Run("Update password updates password changed time", func(t *testing.T) {
		u1, _ := uc.userStore.GetUserByEmail(fakeEmail)
		if u1 == nil {
			t.Error("No user found")
			t.FailNow()
		}

		newPass := "Test new password &$#%"

		_, err := uc.UpdatePassword(u1.(User).GetExtID(), fakePass, newPass)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		u2, _ := uc.userStore.GetUserByEmail(fakeEmail)
		if u2 == nil {
			t.Error("No user found")
			t.FailNow()
		}

		if u1.(User).GetPasswordChanged() == u2.(User).GetPasswordChanged() {
			t.Errorf("Password changed times match (initial: %v new: %v)", u1.(User).GetPasswordChanged(), u2.(User).GetPasswordChanged())
			t.FailNow()
		}
	})

	t.Run("Update password requires correct old password", func(t *testing.T) {

		u, _ := uc.userStore.GetUserByEmail(fakeEmail)

		newPass := "Test new password"

		_, err := uc.UpdatePassword(u.(User).GetExtID(), "wrongPass", newPass)
		if err == nil {
			t.Error(err)
			t.FailNow()
		}
	})

	// Tear down user controller

}
