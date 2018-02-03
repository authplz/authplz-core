/*
 * Core API tests
 * This tests the Core API endpoints
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */
package core

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/authplz/authplz-core/lib/api"
	"github.com/authplz/authplz-core/lib/controllers/datastore"
	"github.com/authplz/authplz-core/lib/events"
	"github.com/authplz/authplz-core/lib/modules/user"
	"github.com/authplz/authplz-core/lib/test"
)

func TestCoreAPI(t *testing.T) {

	ts, err := test.NewTestServer()
	assert.Nil(t, err)

	userModule := user.NewController(ts.DataStore, ts.EventEmitter)

	coreModule := NewController(ts.TokenControl, userModule, ts.EventEmitter)
	coreModule.BindModule("user", userModule)
	coreModule.BindAPI(ts.Router)
	userModule.BindAPI(ts.Router)

	ts.Run()

	v := url.Values{}
	v.Set("email", test.FakeEmail)
	v.Set("password", test.FakePass)
	v.Set("username", test.FakeName)

	client := test.NewClient("http://" + ts.Address() + "/api")

	if _, err := client.PostForm("/create", http.StatusOK, v); err != nil {
		t.Error(err)
		t.FailNow()
	}

	u, _ := ts.DataStore.GetUserByEmail(test.FakeEmail)

	// Activate user and create admin credentals
	user := u.(*datastore.User)
	user.SetActivated(true)
	user.SetAdmin(true)
	ts.DataStore.UpdateUser(user)

	t.Run("Login user", func(t *testing.T) {
		v := url.Values{}
		v.Set("email", test.FakeEmail)
		v.Set("password", test.FakePass)

		client := test.NewClient("http://" + ts.Address() + "/api")

		// Attempt login
		_, err := client.PostForm("/login", http.StatusOK, v)
		assert.Nil(t, err)

		// Check user status
		_, err = client.Get("/status", http.StatusOK)
		assert.Nil(t, err)
	})

	t.Run("Invalid account fails", func(t *testing.T) {
		v := url.Values{}
		v.Set("email", "wrong@email.com")
		v.Set("password", test.FakePass)

		client := test.NewClient("http://" + ts.Address() + "/api")

		// Attempt login
		_, err := client.PostForm("/login", http.StatusUnauthorized, v)
		assert.Nil(t, err)
	})

	t.Run("Invalid password fails", func(t *testing.T) {
		v := url.Values{}
		v.Set("email", test.FakeEmail)
		v.Set("password", "Wrong password")

		client := test.NewClient("http://" + ts.Address() + "/api")

		// Attempt login
		if _, err := client.PostForm("/login", http.StatusUnauthorized, v); err != nil {
			t.Error(err)
			t.FailNow()
		}
	})

	t.Run("Account recovery endpoints work", func(t *testing.T) {
		client := test.NewClient("http://" + ts.Address() + "/api")

		// First, post recovery request to /api/recovery
		v := url.Values{}
		v.Set("email", test.FakeEmail)
		_, err := client.PostForm("/recovery", http.StatusOK, v)
		assert.Nil(t, err)

		// Check for recovery event
		assert.EqualValues(t, events.PasswordResetReq, ts.EventEmitter.Event.GetType())

		// Generate a recovery token
		d, _ := time.ParseDuration("10m")
		token, _ := ts.TokenControl.BuildToken(user.GetExtID(), api.TokenActionRecovery, d)

		// Get recovery endpoint with token
		v = url.Values{}
		v.Set("token", token)
		_, err = client.GetWithParams("/recovery", http.StatusOK, v)
		assert.Nil(t, err)

		// Post new password to user reset endpoint
		newPass := "Reset Password 78@"
		v = url.Values{}
		v.Set("password", newPass)
		_, err = client.PostForm("/reset", http.StatusOK, v)
		assert.Nil(t, err)
	})

}
