package datastore

import "fmt"
import "testing"

func TestDatastore(t *testing.T) {
	// Setup user controller for testing
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Attempt database connection
	ds := NewDataStore(dbString)
	defer ds.Close()

	ds.ForceSync()

	var fakeEmail = "test1@abc.com"
	var fakePass = "abcDEF123@"

	// Run tests
	t.Run("Add user", func(t *testing.T) {
		// Create user
		u, err := ds.AddUser(fakeEmail, fakePass)
		if err != nil {
			t.Error(err)
			return
		}
		if u == nil {
			t.Error("User addition failed")
			return
		}

		u2, err2 := ds.GetUserByEmail(fakeEmail)
		if err2 != nil {
			t.Error(err2)
			return
		}
		if u2 == nil {
			t.Error("User find by email failed")
			return
		}

		if u2.Email != fakeEmail {
			t.Error("Email address mismatch")
			return
		}

	})

	t.Run("Rejects users with invalid emails", func(t *testing.T) {
		// Create user
		_, err := ds.AddUser("abcdef", fakePass)
		if err == nil {
			t.Error("Invalid email allowed")
		}
	})

	t.Run("Finds users by email", func(t *testing.T) {
		// Create user
		u, err := ds.GetUserByEmail(fakeEmail)
		if err != nil {
			t.Error(err)
			return
		}
		if u == nil {
			t.Error("User find by email failed")
			return
		}

		if u.Email != fakeEmail {
			t.Error("Email address mismatch")
			return
		}
	})

	t.Run("Update users", func(t *testing.T) {
		// Create user
		u, err := ds.GetUserByEmail(fakeEmail)
		if err != nil {
			t.Error(err)
			return
		}
		if u == nil {
			t.Error("User find by email failed")
			return
		}

		if u.Password != fakePass {
			t.Error("Initial password mismatch")
			return
		}

		newPassword := "NewPassword"
		u.Password = newPassword

		u, err = ds.UpdateUser(u)
		if err != nil {
			t.Error(err)
			return
		}

		u, err = ds.GetUserByEmail(fakeEmail)
		if err != nil {
			t.Error(err)
			return
		}

		if u.Password != newPassword {
			t.Error("Initial password mismatch")
			return
		}

	})

	t.Skip("Add U2F tokens", func(t *testing.T) {
		// Create user
		u, err := ds.GetUserByEmail(fakeEmail)
		if err != nil {
			t.Error(err)
			return
		}
		if u == nil {
			t.Error("User find by email failed")
			return
		}

		fidoToken := FidoToken{}
		ds.db.Model(u).Association("FidoTokens").Append(fidoToken);

		u, err = ds.GetUserByEmail(fakeEmail)
		if err != nil {
			t.Error(err)
			return
		}

		ds.GetTokens(u);

		fmt.Printf("%+v", u)

		if u.SecondFactors() == false {
			t.Error("No second factors found")
			return
		}
	})


	// Tear down user controller

}
