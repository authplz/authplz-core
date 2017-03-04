package user

import "testing"

import (
	"github.com/ryankurte/authplz/controllers/datastore"
)

func TestUserController(t *testing.T) {
	// Setup user controller for testing
	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@abcDEF123@"
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Attempt database connection
	dataStore, err := datastore.NewDataStore(dbString)
	if err != nil {
		t.Error("Error opening database")
		t.FailNow()
	}

	dataStore.ForceSync()

	// Create controllers
	uc := NewUserModule(dataStore)

	t.Run("Create user", func(t *testing.T) {
		u, err := uc.Create(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
		}
		if u == nil {
			t.Error("User creation failed")
		}
	})

	t.Run("User account requires activation", func(t *testing.T) {
		res, _, err := uc.Login(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.Code != LoginCodeUnactivated {
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
		res, _, err := uc.Login(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.Code != LoginCodeSuccess {
			t.Error("User login failed")
		}
	})

	t.Run("Login updates last login time", func(t *testing.T) {
		u1, _ := uc.userStore.GetUserByEmail(fakeEmail)
		if u1 == nil {
			t.Error("No user found")
			t.FailNow()
		}

		res, _, err := uc.Login(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.Code != LoginCodeSuccess {
			t.Error("User login failed")
		}

		u2, _ := uc.userStore.GetUserByEmail(fakeEmail)
		if u2 == nil {
			t.Error("No user found")
			t.FailNow()
		}

		if u1.(UserInterface).GetLastLogin() == u2.(UserInterface).GetLastLogin() {
			t.Errorf("Login times match (initial: %v new: %v)", u1.(UserInterface).GetLastLogin(), u2.(UserInterface).GetLastLogin())
			t.FailNow()
		}
	})

	t.Run("Reject login with invalid password", func(t *testing.T) {
		res, _, err := uc.Login(fakeEmail, "Wrong password")
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.Code != LoginCodeFailure {
			t.Error("User login succeeded with incorrect password")
		}
	})

	t.Run("Reject login with unknown user", func(t *testing.T) {
		res, _, err := uc.Login("not@email.com", fakePass)
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.Code != LoginCodeFailure {
			t.Error("User login succeeded with unknown email")
		}
	})

	t.Run("Reject login with disabled user account", func(t *testing.T) {

		u, _ := uc.userStore.GetUserByEmail(fakeEmail)
		if u == nil {
			t.Error("No user found")
			t.FailNow()
		}

		u.(UserInterface).SetEnabled(false)
		uc.userStore.UpdateUser(u)

		res, _, err := uc.Login(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.Code != LoginCodeDisabled {
			t.Error("User login succeeded with account disabled")
		}

		u, _ = uc.userStore.GetUserByEmail(fakeEmail)
		u.(UserInterface).SetEnabled(true)
		uc.userStore.UpdateUser(u)
	})

	t.Run("Lock accounts after N logins", func(t *testing.T) {
		for i := 0; i < 6; i++ {
			uc.Login(fakeEmail, "Wrong password")
		}

		res, _, err := uc.Login(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.Code != LoginCodeLocked {
			t.Error("User account was not locked", res)
		}
	})

	t.Run("Unlock accounts", func(t *testing.T) {
		_, err = uc.Unlock(fakeEmail)
		if err != nil {
			t.Error(err)
		}

		res, _, err := uc.Login(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.Code != LoginCodeSuccess {
			t.Error("User account login failed", res)
		}

	})

	t.Run("Get user", func(t *testing.T) {

		u, _ := uc.userStore.GetUserByEmail(fakeEmail)
		if u == nil {
			t.Error("No user found")
			t.FailNow()
		}

		u1, err := uc.GetUser(u.(UserInterface).GetExtId())
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

		_, err := uc.UpdatePassword(u.(UserInterface).GetExtId(), fakePass, newPass)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		res, _, err := uc.Login(fakeEmail, newPass)
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.Code != LoginCodeSuccess {
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

		_, err := uc.UpdatePassword(u1.(UserInterface).GetExtId(), fakePass, newPass)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		u2, _ := uc.userStore.GetUserByEmail(fakeEmail)
		if u2 == nil {
			t.Error("No user found")
			t.FailNow()
		}

		if u1.(UserInterface).GetPasswordChanged() == u2.(UserInterface).GetPasswordChanged() {
			t.Errorf("Password changed times match (initial: %v new: %v)", u1.(UserInterface).GetPasswordChanged(), u2.(UserInterface).GetPasswordChanged())
			t.FailNow()
		}
	})

	t.Run("Update password requires correct old password", func(t *testing.T) {

		u, _ := uc.userStore.GetUserByEmail(fakeEmail)

		newPass := "Test new password"

		_, err := uc.UpdatePassword(u.(UserInterface).GetExtId(), "wrongPass", newPass)
		if err == nil {
			t.Error(err)
			t.FailNow()
		}
	})

	// Tear down user controller

}
