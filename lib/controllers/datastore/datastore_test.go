/* AuthPlz Authentication and Authorization Microservice
 * Datastore - tests
 *
 * Copyright 2018 Ryan Kurte
 */

package datastore

import (
	"fmt"
	"testing"

	"github.com/authplz/authplz-core/lib/config"
)

func TestDatastore(t *testing.T) {

	c, _ := config.DefaultConfig()

	// Attempt database connection
	ds, err := NewDataStore(c.Database)
	if err != nil {
		t.Errorf("%s", err)
		t.FailNow()
	}
	defer ds.Close()

	ds.ForceSync()

	var fakeEmail = "test1@abc.com"
	var fakePass = "abcDEF123@"
	var fakeName = "user.sdfsfdF"

	// Run tests
	t.Run("Add user", func(t *testing.T) {
		// Create user
		u, err := ds.AddUser(fakeEmail, fakeName, fakePass)
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

		u2inst := u2.(*User)

		if u2inst.GetEmail() != fakeEmail {
			t.Error("Email address mismatch")
			return
		}

	})

	t.Run("Rejects users with invalid emails", func(t *testing.T) {
		// Create user
		_, err := ds.AddUser("abcdef", fakeName, fakePass)
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
		userInst := u.(*User)

		if userInst.GetEmail() != fakeEmail {
			t.Error("Email address mismatch")
			return
		}
	})

	t.Run("Finds users by uuid", func(t *testing.T) {
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

		userInst := u.(*User)

		u, err = ds.GetUserByExtID(userInst.GetExtID())
		if err != nil {
			t.Error(err)
			return
		}
		if u == nil {
			t.Error("User find by UserId failed")
			return
		}

		userInst = u.(*User)

		if userInst.GetEmail() != fakeEmail {
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

		userInst := u.(*User)

		if userInst.GetPassword() != fakePass {
			t.Error("Initial password mismatch")
			return
		}

		newPassword := "NewPassword"
		userInst.SetPassword(newPassword)

		_, err = ds.UpdateUser(userInst)
		if err != nil {
			t.Error(err)
			return
		}

		u, err = ds.GetUserByEmail(fakeEmail)
		if err != nil {
			t.Error(err)
			return
		}

		userInst = u.(*User)

		if userInst.GetPassword() != newPassword {
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
		ds.db.Model(u).Association("FidoTokens").Append(fidoToken)

		u, err = ds.GetUserByEmail(fakeEmail)
		if err != nil {
			t.Error(err)
			return
		}

		ds.GetTokens(u)

		fmt.Printf("%+v", u)

		userInst := u.(*User)

		if userInst.SecondFactors() == false {
			t.Error("No second factors found")
			return
		}
	})

	// Tear down user controller

}
