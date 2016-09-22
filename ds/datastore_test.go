package ds

import "fmt"
import "testing"

func TestDatastore(t *testing.T) {
	// Setup user controller for testing
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Attempt database connection
	ds := NewDataStore(dbString)
	defer ds.Close()

	ds.db.DropTableIfExists(&User{})
	ds.db.AutoMigrate(&User{})
	ds.db.DropTableIfExists(&FidoToken{})
	ds.db.AutoMigrate(&FidoToken{})
	ds.db.DropTableIfExists(&TotpToken{})
	ds.db.AutoMigrate(&TotpToken{})
	ds.db.DropTableIfExists(&AuditEvent{})
	ds.db.AutoMigrate(&AuditEvent{})

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

	t.Run("Add U2F tokens", func(t *testing.T) {
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
		u.FidoTokens = append(u.FidoTokens, fidoToken)

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

		fmt.Printf("%+v", u)

		if u.SecondFactors() == false {
			t.Error("No second factors found")
			return
		}

	})

	// Tear down user controller

}
