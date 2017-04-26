package app

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	_totp "github.com/pquerna/otp/totp"
	"github.com/ryankurte/go-u2f"
	"github.com/stretchr/testify/assert"

	"github.com/ryankurte/authplz/lib/api"
	"github.com/ryankurte/authplz/lib/config"
	"github.com/ryankurte/authplz/lib/controllers/datastore"
	"github.com/ryankurte/authplz/lib/modules/2fa/totp"
	"github.com/ryankurte/authplz/lib/test"
)

func TestMain(t *testing.T) {

	// Fetch default configuration
	c, err := config.GetConfig()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// Set test constants
	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@abcDEF123"
	var fakeName = "test.user99"
	var userID = ""

	// Attempt database connection
	c.NoTLS = true
	c.ExternalAddress = fmt.Sprintf("http://%s:%s", c.Address, c.Port)
	c.AllowedOrigins = []string{c.ExternalAddress, "https://authplz.herokuapp.com"}

	server := NewServer(*c)

	// Force database synchronization
	server.ds.ForceSync()

	// Launch server process
	go server.Start()
	defer server.Close()

	// Setup test helpers
	apiPath := "http://" + c.Address + ":" + c.Port + "/api"

	client := test.NewTestClient(apiPath)

	vt, _ := u2f.NewVirtualKey()

	// Run tests
	t.Run("Login status", func(t *testing.T) {
		resp, err := client.Get("/status", http.StatusOK)
		if err != nil {
			t.Error(err)
		}
		if err := test.ParseAndCheckAPIResponse(resp, api.ResultError, api.GetAPILocale(api.DefaultLocale).Unauthorized); err != nil {
			t.Error(err)
		}
	})

	t.Run("Check default CORS header", func(t *testing.T) {
		req, err := http.NewRequest("OPTIONS", apiPath+"/status", http.NoBody)
		assert.Nil(t, err)

		resp, err := client.Do(req)
		assert.Nil(t, err)

		assert.EqualValues(t, "http://"+c.Address+":"+c.Port, c.AllowedOrigins[0])

		assert.NotNil(t, resp)
		assert.EqualValues(t, c.ExternalAddress, resp.Header.Get("access-control-allow-origin"))
	})

	t.Run("Check additional CORS header", func(t *testing.T) {
		req, err := http.NewRequest("OPTIONS", apiPath+"/status", http.NoBody)
		assert.Nil(t, err)
		req.Header.Set("origin", c.AllowedOrigins[1])

		resp, err := client.Do(req)
		assert.Nil(t, err)

		assert.NotNil(t, resp)
		assert.EqualValues(t, c.AllowedOrigins[1], resp.Header.Get("access-control-allow-origin"))
	})

	t.Run("Check CORS header mismatch", func(t *testing.T) {
		req, err := http.NewRequest("OPTIONS", apiPath+"/status", http.NoBody)
		assert.Nil(t, err)
		req.Header.Set("origin", "https://yolo-swag.com")

		resp, err := client.Do(req)
		assert.Nil(t, err)

		assert.NotNil(t, resp)
		assert.EqualValues(t, c.AllowedOrigins[0], resp.Header.Get("access-control-allow-origin"))
	})

	t.Run("Create User", func(t *testing.T) {

		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		v.Set("username", fakeName)

		if _, err := client.PostForm("/create", http.StatusOK, v); err != nil {
			t.Error(err)
		}

		u, _ := server.ds.GetUserByEmail(fakeEmail)

		user := u.(*datastore.User)
		userID = user.GetExtID()
	})

	t.Run("User loaded", func(t *testing.T) {
		if userID == "" {
			t.Errorf("User loading failed")
			t.FailNow()
		}
	})

	t.Run("Login fails prior to activation", func(t *testing.T) {

		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)

		if _, err := client.PostForm("/login", http.StatusUnauthorized, v); err != nil {
			t.Error(err)
		}
	})

	t.Run("Account activation requires valid activation token", func(t *testing.T) {

		// Create activation token
		d, _ := time.ParseDuration("-10m")
		at, _ := server.tokenControl.BuildToken(userID, api.TokenActionActivate, d)

		// Use a separate test client instance
		client2 := test.NewTestClient(apiPath)
		// Post activation token
		v := url.Values{}
		v.Set("token", at)

		if _, err := client2.PostForm("/action", http.StatusOK, v); err != nil {
			t.Error(err)
		}

		// Attempt login with activation cookie
		v = url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		if _, err := client2.PostForm("/action", http.StatusBadRequest, v); err != nil {
			t.Error(err)
		}

		// Check user status
		resp, err := client2.Get("/status", http.StatusOK)
		if err != nil {
			t.Error(err)
		}
		if err := test.ParseAndCheckAPIResponse(resp, api.ResultError, api.GetAPILocale(api.DefaultLocale).Unauthorized); err != nil {
			t.Error(err)
		}
	})

	t.Run("Accounts can be activated", func(t *testing.T) {

		// Create activation token
		d, _ := time.ParseDuration("10m")
		at, _ := server.tokenControl.BuildToken(userID, api.TokenActionActivate, d)

		// Use a separate test client instance
		client2 := test.NewTestClient(apiPath)

		// Post activation token
		v := url.Values{}
		v.Set("token", at)
		if _, err := client2.PostForm("/action", http.StatusOK, v); err != nil {
			t.Error(err)
		}

		// Attempt login with activation cookie
		v = url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		if _, err := client2.PostForm("/login", http.StatusOK, v); err != nil {
			t.Error(err)
		}

		// Check user status
		resp, err := client2.Get("/status", http.StatusOK)
		if err != nil {
			t.Error(err)
		}
		if err := test.ParseAndCheckAPIResponse(resp, api.ResultOk, api.GetAPILocale(api.DefaultLocale).LoginSuccessful); err != nil {
			t.Error(err)
		}
	})

	t.Run("Activated users can login", func(t *testing.T) {

		// Attempt login
		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		if _, err := client.PostForm("/login", http.StatusOK, v); err != nil {
			t.Error(err)
		}

		// Check user status
		resp, err := client.Get("/status", http.StatusOK)
		if err != nil {
			t.Error(err)
		}
		if err := test.ParseAndCheckAPIResponse(resp, api.ResultOk, api.GetAPILocale(api.DefaultLocale).LoginSuccessful); err != nil {
			t.Error(err)
		}
	})

	t.Run("Accounts are locked after N attempts", func(t *testing.T) {

		client2 := test.NewTestClient(apiPath)

		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", "WrongPass")

		// Attempt login to cause account lock
		for i := 0; i < 10; i++ {
			if _, err := client2.PostForm("/login", http.StatusUnauthorized, v); err != nil {
				t.Error(err)
			}
		}

		// Check user status
		resp, err := client2.Get("/status", http.StatusOK)
		if err != nil {
			t.Error(err)
		}
		if err := test.ParseAndCheckAPIResponse(resp, api.ResultError, api.GetAPILocale(api.DefaultLocale).Unauthorized); err != nil {
			t.Error(err)
		}

		// Set to correct password
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)

		// Check login still fails
		if _, err := client2.PostForm("/login", http.StatusUnauthorized, v); err != nil {
			t.Error(err)
		}
	})

	t.Run("Account unlock requires valid unlock token", func(t *testing.T) {

		// Use a separate test client instance
		client2 := test.NewTestClient(apiPath)

		// Create activation token
		d, _ := time.ParseDuration("-10m")
		at, _ := server.tokenControl.BuildToken(userID, api.TokenActionUnlock, d)

		// Post activation token
		v := url.Values{}
		v.Set("token", at)
		if _, err := client2.PostForm("/action", http.StatusOK, v); err != nil {
			t.Error(err)
		}

		// Attempt login with activation cookie
		v = url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		if _, err := client2.PostForm("/login", http.StatusBadRequest, v); err != nil {
			t.Error(err)
		}

		// Check user status
		resp, err := client2.Get("/status", http.StatusOK)
		if err != nil {
			t.Error(err)
		}
		if err := test.ParseAndCheckAPIResponse(resp, api.ResultError, api.GetAPILocale(api.DefaultLocale).Unauthorized); err != nil {
			t.Error(err)
		}
	})

	t.Run("Locked accounts can be unlocked", func(t *testing.T) {

		// Use a separate test client instance
		client2 := test.NewTestClient(apiPath)

		// Create activation token
		d, _ := time.ParseDuration("10m")
		at, _ := server.tokenControl.BuildToken(userID, api.TokenActionUnlock, d)

		// Post activation token
		v := url.Values{}
		v.Set("token", at)
		if _, err := client2.PostForm("/action", http.StatusOK, v); err != nil {
			t.Error(err)
		}

		// Attempt login with activation cookie
		v = url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		if _, err := client2.PostForm("/login", http.StatusOK, v); err != nil {
			t.Error(err)
		}

		// Check user status
		resp, err := client2.Get("/status", http.StatusOK)
		if err != nil {
			t.Error(err)
		}
		if err := test.ParseAndCheckAPIResponse(resp, api.ResultOk, api.GetAPILocale(api.DefaultLocale).LoginSuccessful); err != nil {
			t.Error(err)
		}
	})

	t.Run("Logged in users can get account info", func(t *testing.T) {
		var u datastore.User

		resp, err := client.Get("/account", http.StatusOK)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		err = test.ParseJson(resp, &u)
		if err != nil {
			t.Error(err)
		}

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

		resp, err := client.PostForm("/account", http.StatusOK, v)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		err = test.ParseAndCheckAPIResponse(resp, api.ResultOk, api.GetAPILocale(api.DefaultLocale).PasswordUpdated)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		fakePass = newPass
	})

	t.Run("Users can request password resets", func(t *testing.T) {
		client2 := test.NewTestClient(apiPath)

		// First, post recovery request to /api/recovery
		v := url.Values{}
		v.Set("email", fakeEmail)
		if _, err := client2.PostForm("/recovery", http.StatusOK, v); err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Generate a recovery token
		d, _ := time.ParseDuration("10m")
		token, _ := server.tokenControl.BuildToken(userID, api.TokenActionRecovery, d)

		// Get recovery endpoint with token
		v = url.Values{}
		v.Set("token", token)
		if _, err := client2.GetWithParams("/recovery", http.StatusOK, v); err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Post new password to user reset endpoint
		newPass := "Reset Password 78@"
		v = url.Values{}
		v.Set("password", newPass)
		if _, err := client2.PostForm("/reset", http.StatusOK, v); err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Update fakePass for further calls
		fakePass = newPass
	})

	t.Run("Password reset requests rejected across clients", func(t *testing.T) {
		client2 := test.NewTestClient(apiPath)
		client3 := test.NewTestClient(apiPath)

		// First, post recovery request to /api/recovery
		v := url.Values{}
		v.Set("email", fakeEmail)
		if _, err := client2.PostForm("/recovery", http.StatusOK, v); err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Generate a recovery token
		d, _ := time.ParseDuration("10m")
		token, _ := server.tokenControl.BuildToken(userID, api.TokenActionRecovery, d)

		// Get recovery endpoint with token
		v = url.Values{}
		v.Set("token", token)
		if _, err := client3.GetWithParams("/recovery", http.StatusBadRequest, v); err != nil {
			t.Error(err)
			t.FailNow()
		}
	})

	t.Run("Password reset submissions rejected across clients", func(t *testing.T) {
		client2 := test.NewTestClient(apiPath)
		client3 := test.NewTestClient(apiPath)

		// First, post recovery request to /api/recovery
		v := url.Values{}
		v.Set("email", fakeEmail)
		if _, err := client2.PostForm("/recovery", http.StatusOK, v); err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Generate a recovery token
		d, _ := time.ParseDuration("10m")
		token, _ := server.tokenControl.BuildToken(userID, api.TokenActionRecovery, d)

		// Get recovery endpoint with token
		v = url.Values{}
		v.Set("token", token)
		if _, err := client2.GetWithParams("/recovery", http.StatusOK, v); err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Post new password to user reset endpoint
		newPass := "Reset Password 78@"
		v = url.Values{}
		v.Set("password", newPass)
		if _, err := client3.PostForm("/reset", http.StatusBadRequest, v); err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Update fakePass for further calls
		fakePass = newPass
	})

	t.Run("Users must be logged in to update passwords", func(t *testing.T) {
		//TODO
	})

	t.Run("Logged in users can enrol fido tokens", func(t *testing.T) {
		v := url.Values{}
		v.Set("name", "fakeToken")

		// Generate enrolment request
		var rr u2f.RegisterRequestMessage
		resp, err := client.GetWithParams("/u2f/enrol", http.StatusOK, v)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		err = test.ParseJson(resp, &rr)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Check AppId is set correctly
		if rr.AppID != c.ExternalAddress {
			t.Errorf("U2F challenge AppId mismatch (expected %s received %s)", c.ExternalAddress, rr.AppID)
			t.FailNow()
		}

		// Handle via virtual token
		registerResp, err := vt.HandleRegisterRequest(rr)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Post registration response back
		resp, err = client.PostJSON("/u2f/enrol", http.StatusOK, registerResp)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		err = test.ParseAndCheckAPIResponse(resp, api.ResultOk, api.GetAPILocale(api.DefaultLocale).U2FRegistrationComplete)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
	})

	t.Run("Logged in users can list fido tokens", func(t *testing.T) {
		var regs []u2f.Registration
		if err := client.GetJSON("/u2f/tokens", 200, &regs); err != nil {
			t.Error(err)
			t.FailNow()
		}

		if len(regs) != 1 {
			t.Errorf("No registrations returned")
		}
	})

	var totpSecret = ""

	t.Run("Logged in users can enrol totp tokens", func(t *testing.T) {
		// Generate enrolment request
		v := url.Values{}
		v.Set("name", "fakeToken")
		var rc totp.RegisterChallenge
		if err := client.GetJSONWithParams("/totp/enrol", http.StatusOK, v, &rc); err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Check Name is set correctly
		if rc.Issuer != c.Name {
			t.Errorf("TOTP challenge Issuer mismatch (expected %s received %s)", c.Name, rc.Issuer)
			t.FailNow()
		}

		if rc.AccountName != fakeEmail {
			t.Errorf("TOTP challenge Name mismatch (expected %s received %s)", rc.AccountName, fakeEmail)
			t.FailNow()
		}

		// Generate challenge response
		code, err := _totp.GenerateCode(rc.Secret, time.Now())
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		v = url.Values{}
		v.Set("code", code)
		// Post registration response back
		if _, err := client.PostForm("/totp/enrol", http.StatusOK, v); err != nil {
			t.Error(err)
		}

		totpSecret = rc.Secret
	})

	t.Run("Logged in users can list totp tokens", func(t *testing.T) {
		var tokens []totp.TokenResp
		if err := client.GetJSON("/totp/tokens", 200, &tokens); err != nil {
			t.Error(err)
		}

		if len(tokens) != 1 {
			t.Errorf("No registrations returned")
		}
	})

	t.Run("Second factor required for login", func(t *testing.T) {
		client2 := test.NewTestClient(apiPath)

		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)

		if _, err := client2.PostForm("/login", http.StatusAccepted, v); err != nil {
			t.Error(err)
		}

		if err := client2.GetAPIResponse("/status", http.StatusOK, api.ResultError, api.GetAPILocale(api.DefaultLocale).Unauthorized); err != nil {
			t.Error(err)
		}
	})

	t.Run("Second factor allows login (u2f)", func(t *testing.T) {

		client2 := test.NewTestClient(apiPath)

		// Start login
		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		if _, err := client2.PostForm("/login", http.StatusAccepted, v); err != nil {
			t.Error(err)
		}

		// Fetch U2F request
		var sr u2f.SignRequestMessage
		if err := client2.GetJSON("/u2f/authenticate", 200, &sr); err != nil {
			t.Error(err)
		}

		if sr.AppID != c.ExternalAddress {
			t.Errorf("U2F register AppId mismatch (expected %s received %s)", c.ExternalAddress, sr.AppID)
		}

		// Handle via virtual token
		signResp, err := vt.HandleAuthenticationRequest(sr)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Post response and check login status
		resp, err := client2.PostJSON("/u2f/authenticate", http.StatusOK, signResp)
		if err != nil {
			t.Error(err)
		}
		if err = test.ParseAndCheckAPIResponse(resp, api.ResultOk, api.GetAPILocale(api.DefaultLocale).LoginSuccessful); err != nil {
			t.Error(err)
		}

		if err := client2.GetAPIResponse("/status", http.StatusOK, api.ResultOk, api.GetAPILocale(api.DefaultLocale).LoginSuccessful); err != nil {
			t.Error(err)
		}

	})

	t.Run("Second factor allows login (totp)", func(t *testing.T) {

		client2 := test.NewTestClient(apiPath)

		// Start login
		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		if _, err := client2.PostForm("/login", http.StatusAccepted, v); err != nil {
			t.Error(err)
		}

		// Generate challenge response
		code, err := _totp.GenerateCode(totpSecret, time.Now())
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Post response and check login status
		v = url.Values{}
		v.Set("code", code)
		if _, err := client2.PostForm("/totp/authenticate", http.StatusOK, v); err != nil {
			t.Error(err)
		}

		if err := client2.GetAPIResponse("/status", http.StatusOK, api.ResultOk, api.GetAPILocale(api.DefaultLocale).LoginSuccessful); err != nil {
			t.Error(err)
		}

	})

	t.Run("Users can request password resets with 2fa", func(t *testing.T) {
		client2 := test.NewTestClient(apiPath)

		// First, post recovery request to /api/recovery
		v := url.Values{}
		v.Set("email", fakeEmail)
		if _, err := client2.PostForm("/recovery", http.StatusOK, v); err != nil {
			t.Error(err)
		}

		// Generate a recovery token
		d, _ := time.ParseDuration("10m")
		token, _ := server.tokenControl.BuildToken(userID, api.TokenActionRecovery, d)

		// Get recovery endpoint with token
		v = url.Values{}
		v.Set("token", token)
		if _, err := client2.GetWithParams("/recovery", http.StatusAccepted, v); err != nil {
			t.Error(err)
		}

		// Generate 2fa response
		code, err := _totp.GenerateCode(totpSecret, time.Now())
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		// Post 2fa response
		v = url.Values{}
		v.Set("code", code)
		if _, err := client2.PostForm("/totp/authenticate", http.StatusOK, v); err != nil {
			t.Error(err)
		}

		// Post new password to user reset endpoint
		newPass := "Reset Password 78@ cats"
		v = url.Values{}
		v.Set("password", newPass)
		if _, err := client2.PostForm("/reset", http.StatusOK, v); err != nil {
			t.Error(err)
		}

		// Update fakePass for further calls
		fakePass = newPass
	})

	t.Run("Logged in users can logout", func(t *testing.T) {

		// Perform logout
		if _, err := client.Get("/logout", 200); err != nil {
			t.Error(err)
		}

		// Check user status
		if err := client.GetAPIResponse("/status", http.StatusOK, api.ResultError, api.GetAPILocale(api.DefaultLocale).Unauthorized); err != nil {
			t.Error(err)
		}
	})

}
