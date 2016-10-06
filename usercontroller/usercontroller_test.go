package usercontroller

import "testing"

import "github.com/ryankurte/authplz/datastore"

func TestUserController(t *testing.T) {
	// Setup user controller for testing
	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@"
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Attempt database connection
	ds := datastore.NewDataStore(dbString)

	ds.ForceSync()

	// Create controllers
	uc := NewUserController(&ds, nil)

	// Run tests
	t.Run("Create user", func(t *testing.T) {
		u, err := uc.CreateUser(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
		}
		if u == nil {
			t.Error("User creation failed")
		}
	})

	t.Run("User account requires activation", func(t *testing.T) {
		res, err := uc.Login(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.code != LoginUnactivated {
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
		res, err := uc.Login(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.code != LoginSuccess {
			t.Error("User login failed")
		}
	})

	t.Run("Reject login with invalid password", func(t *testing.T) {
		res, err := uc.Login(fakeEmail, "Wrong password")
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.code != LoginFailure {
			t.Error("User login succeeded with incorrect password")
		}
	})

	t.Run("Reject login with unknown user", func(t *testing.T) {
		res, err := uc.Login("not@email.com", fakePass)
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.code != LoginFailure {
			t.Error("User login succeeded with unknown email")
		}
	})

	t.Run("Reject login with disabled user account", func(t *testing.T) {

		u, _ := uc.userStore.GetUserByEmail(fakeEmail)
		if u == nil {
			t.Error("No user found")
			t.FailNow()
		}

		u.Enabled = false
		uc.userStore.UpdateUser(u)

		res, err := uc.Login(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.code != LoginDisabled {
			t.Error("User login succeeded with account disabled")
		}

		u, _ = uc.userStore.GetUserByEmail(fakeEmail)
		u.Enabled = true
		uc.userStore.UpdateUser(u)
	})

	t.Run("Lock accounts after N logins", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			uc.Login(fakeEmail, "Wrong password")
		}

		res, err := uc.Login(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
		}
		if res == nil {
			t.Error("No login result")
			t.FailNow()
		}
		if res.code != LoginLocked {
			t.Error("User account was not locked", res)
		}
	})

	// Tear down user controller

}
