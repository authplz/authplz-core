package app

import "testing"

//import "fmt"
import "time"
import "net/http"
import "net/url"

import "github.com/ryankurte/go-u2f"

import "github.com/ryankurte/authplz/datastore"
import "github.com/ryankurte/authplz/token"
import "github.com/ryankurte/authplz/api"

func (tc *TestClient) TestPostFormGetJson(t *testing.T, path string, v url.Values, responseInst interface{}) {
	tc.BindTest(t).TestPostForm(path, http.StatusOK, v).TestParseJson(responseInst)
}

func (tc *TestClient) TestPostJsonGetJson(t *testing.T, path string, requestInst interface{}, responseInst interface{}) {
	tc.BindTest(t).TestPostJson(path, http.StatusOK, requestInst).TestParseJson(responseInst)
}

func (tc *TestClient) TestCheckApiResponse(t *testing.T, status api.ApiResponse, result string, message string) {
	if status.Result != result {
		t.Errorf("Incorrect API result, expected: %s received: %s message: %s", result, status.Result, status.Message)
		t.FailNow()
	}

	if status.Message != message {
		t.Errorf("Incorrect API message, expected: %s received: %s", message, status.Message)
		t.FailNow()
	}
}

func (tc *TestClient) TestGetApiResponse(t *testing.T, path string, result string, message string) {
	var status api.ApiResponse
	tc.BindTest(t).TestGet(path, http.StatusOK).TestParseJson(&status)
	tc.TestCheckApiResponse(t, status, result, message)
}

func (tc *TestClient) TestPostApiResponse(t *testing.T, path string, v url.Values, result string, message string) {
	var status api.ApiResponse
	tc.TestPostFormGetJson(t, path, v, &status)
	tc.TestCheckApiResponse(t, status, result, message)
}

func (tc *TestClient) TestPostJsonCheckApiResponse(t *testing.T, path string, inst interface{}, result string, message string) {
	var status api.ApiResponse
	tc.TestPostJsonGetJson(t, path, inst, &status)
	tc.TestCheckApiResponse(t, status, result, message)
}

func TestMain(t *testing.T) {

	// Fetch default configuration
	c, err := DefaultConfig()
	if err != nil {
		t.Error(err.Error())
	}

	// Set test constants
	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@"

	// Attempt database connection
	c.NoTls = true
	server := NewServer(*c)

	// Force database synchronization
	server.ds.ForceSync()

	// Launch server process
	go server.Start()
	defer server.Close()

	// Setup test helpers
	apiPath := "http://" + c.Address + ":" + c.Port + "/api"

	client := NewTestClient(apiPath)
	var user *datastore.User

	vt, _ := u2f.NewVirtualKey()

	// Run tests
	t.Run("Login status", func(t *testing.T) {
		client.TestGetApiResponse(t, "/status", api.ApiResultError, api.ApiMessageUnauthorized)
	})

	t.Run("Create User", func(t *testing.T) {

		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)

		client.BindTest(t).TestPostForm("/create", http.StatusOK, v)

		user, _ = server.ds.GetUserByEmail(fakeEmail)
	})

	t.Run("Login fails prior to activation", func(t *testing.T) {

		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)

		client.BindTest(t).TestPostForm("/login", http.StatusUnauthorized, v)
	})

	t.Run("Account activation requires valid activation token subject", func(t *testing.T) {

		// Create activation token
		d, _ := time.ParseDuration("10m")
		at, _ := server.ctx.tokenController.BuildToken("blah", token.TokenActionActivate, d)

		// Use a separate test client instance
		client2 := NewTestClient(apiPath)
		// Post activation token
		v := url.Values{}
		v.Set("token", at)
		client2.BindTest(t).TestPostForm("/action", http.StatusOK, v)

		// Attempt login with activation cookie
		v = url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		client2.BindTest(t).TestPostForm("/login", http.StatusUnauthorized, v)

		// Check user status
		client2.TestGetApiResponse(t, "/status", api.ApiResultError, api.ApiMessageUnauthorized)
	})

	t.Run("Accounts can be activated", func(t *testing.T) {

		// Create activation token
		d, _ := time.ParseDuration("10m")
		at, _ := server.ctx.tokenController.BuildToken(user.ExtId, token.TokenActionActivate, d)

		// Use a separate test client instance
		client2 := NewTestClient(apiPath)

		// Post activation token
		v := url.Values{}
		v.Set("token", at)
		client2.BindTest(t).TestPostForm("/action", http.StatusOK, v)

		// Attempt login with activation cookie
		v = url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		client2.BindTest(t).TestPostForm("/login", http.StatusOK, v)

		// Check user status
		client2.TestGetApiResponse(t, "/status", api.ApiResultOk, api.ApiMessageLoginSuccess)
	})

	t.Run("Activated users can login", func(t *testing.T) {

		// Attempt login
		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		client.BindTest(t).TestPostForm("/login", http.StatusOK, v)

		// Check user status
		client.TestGetApiResponse(t, "/status", api.ApiResultOk, api.ApiMessageLoginSuccess)
	})

	t.Run("Accounts are locked after N attempts", func(t *testing.T) {

		client2 := NewTestClient(apiPath)

		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", "WrongPass")

		// Attempt login to cause account lock
		for i := 0; i < 10; i++ {
			client2.BindTest(t).TestPostForm("/login", http.StatusUnauthorized, v)
		}

		// Check user status
		client2.TestGetApiResponse(t, "/status", api.ApiResultError, api.ApiMessageUnauthorized)

		// Set to correct password
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)

		// Check login still fails
		client2.BindTest(t).TestPostForm("/login", http.StatusUnauthorized, v)
	})

	t.Run("Account unlock requires valid unlock token subject", func(t *testing.T) {

		// Use a separate test client instance
		client2 := NewTestClient(apiPath)

		// Create activation token
		d, _ := time.ParseDuration("10m")
		at, _ := server.ctx.tokenController.BuildToken("blah", token.TokenActionUnlock, d)

		// Post activation token
		v := url.Values{}
		v.Set("token", at)
		client2.BindTest(t).TestPostForm("/action", http.StatusOK, v)

		// Attempt login with activation cookie
		v = url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		client2.BindTest(t).TestPostForm("/login", http.StatusUnauthorized, v)

		// Check user status
		client2.TestGetApiResponse(t, "/status", api.ApiResultError, api.ApiMessageUnauthorized)
	})

	t.Run("Locked accounts can be unlocked", func(t *testing.T) {

		// Create activation token
		d, _ := time.ParseDuration("10m")
		at, _ := server.ctx.tokenController.BuildToken(user.ExtId, token.TokenActionUnlock, d)

		// Use a separate test client instance
		client2 := NewTestClient(apiPath)

		// Post activation token
		v := url.Values{}
		v.Set("token", at)
		client2.BindTest(t).TestPostForm("/action", http.StatusOK, v)

		// Attempt login with activation cookie
		v = url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		client2.BindTest(t).TestPostForm("/login", http.StatusOK, v)

		// Check user status
		client2.TestGetApiResponse(t, "/status", api.ApiResultOk, api.ApiMessageLoginSuccess)
	})

	t.Run("Logged in users can get account info", func(t *testing.T) {
		var u datastore.User
		client.BindTest(t).TestGet("/account", http.StatusOK).TestParseJson(&u)

		if u.Email != fakeEmail {
			t.Errorf("Email mismatch")
		}
	})

	t.Run("Logged in users can update passwords", func(t *testing.T) {

		v := url.Values{}
		newPass := "New fake password 88@#"

		v.Set("email", fakeEmail)
		v.Set("old_password", fakePass)
		v.Set("new_password", newPass)

		var status api.ApiResponse
		client.BindTest(t).TestPostForm("/account", http.StatusOK, v).TestParseJson(&status)
		client.TestCheckApiResponse(t, status, api.ApiResultOk, api.ApiMessagePasswordUpdated)

		fakePass = newPass
	})

	t.Skip("Users must be logged in to update passwords", func(t *testing.T) {
		//TODO
	})

	t.Run("Logged in users can enrol tokens", func(t *testing.T) {
		// Generate enrolment request
		var rr u2f.RegisterRequestMessage
		client.BindTest(t).TestGet("/u2f/enrol", 200).TestParseJson(&rr)

		// Check AppId is set correctly
		if rr.AppID != c.Address {
			t.Errorf("U2F challenge AppId mismatch")
		}

		// Handle via virtual token
		resp, err := vt.HandleRegisterRequest(rr)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Post registration response back
		client.TestPostJsonCheckApiResponse(t, "/u2f/enrol", resp, api.ApiResultOk, api.ApiMessageU2FRegistrationComplete)
	})

	t.Run("Logged in users can list tokens", func(t *testing.T) {
		var regs []u2f.Registration
		client.BindTest(t).TestGet("/u2f/status", 200).TestParseJson(&regs)

		if len(regs) != 1 {
			t.Errorf("No registrations returned")
		}
	})

	t.Run("Second factor required for login", func(t *testing.T) {
		client2 := NewTestClient(apiPath)

		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)

		client2.BindTest(t).TestPostForm("/login", http.StatusAccepted, v)
		client2.TestGetApiResponse(t, "/status", api.ApiResultError, api.ApiMessageUnauthorized)
	})

	t.Run("Second factor allows login", func(t *testing.T) {

		client2 := NewTestClient(apiPath)

		// Start login
		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)

		client2.BindTest(t).TestPostForm("/login", http.StatusAccepted, v)

		// Fetch U2F request
		var sr u2f.SignRequestMessage
		client2.BindTest(t).TestGet("/u2f/authenticate", 200).TestParseJson(&sr)

		if sr.AppID != c.Address {
			t.Errorf("U2F challenge AppId mismatch")
		}

		// Handle via virtual token
		resp, err := vt.HandleAuthenticationRequest(sr)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Post response and check login status
		client2.TestPostJsonCheckApiResponse(t, "/u2f/authenticate", resp, api.ApiResultOk, api.ApiMessageLoginSuccess)
		client2.TestGetApiResponse(t, "/status", api.ApiResultOk, api.ApiMessageLoginSuccess)

	})

	t.Run("Logged in users can logout", func(t *testing.T) {

		// Perform logout
		client.TestGetApiResponse(t, "/logout", api.ApiResultOk, api.ApiMessageLogoutSuccess)

		// Check user status
		client.TestGetApiResponse(t, "/status", api.ApiResultError, api.ApiMessageUnauthorized)
	})

}
