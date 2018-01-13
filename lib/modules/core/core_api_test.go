package core

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/authplz/authplz-core/lib/controllers/datastore"
	"github.com/authplz/authplz-core/lib/modules/user"
	"github.com/authplz/authplz-core/lib/test"
)

func TestCore(t *testing.T) {

	ts, err := test.NewTestServer()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

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

	client := test.NewTestClient("http://" + test.Address + "/api")

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

		client := test.NewTestClient("http://" + test.Address + "/api")

		// Attempt login
		if _, err := client.PostForm("/login", http.StatusOK, v); err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Check user status
		if _, err = client.Get("/status", http.StatusOK); err != nil {
			t.Error(err)
			t.FailNow()
		}
	})

	t.Run("Invalid account fails", func(t *testing.T) {
		v := url.Values{}
		v.Set("email", "wrong@email.com")
		v.Set("password", test.FakePass)

		client := test.NewTestClient("http://" + test.Address + "/api")

		// Attempt login
		if _, err := client.PostForm("/login", http.StatusUnauthorized, v); err != nil {
			t.Error(err)
			t.FailNow()
		}
	})

	t.Run("Invalid password fails", func(t *testing.T) {
		v := url.Values{}
		v.Set("email", test.FakeEmail)
		v.Set("password", "Wrong password")

		client := test.NewTestClient("http://" + test.Address + "/api")

		// Attempt login
		if _, err := client.PostForm("/login", http.StatusUnauthorized, v); err != nil {
			t.Error(err)
			t.FailNow()
		}
	})

}
