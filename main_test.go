package main

import "testing"
//import "fmt"
import "bytes"
import "time"
import "net/http"
import "net/url"
import "net/http/cookiejar"

import "encoding/json"

import "github.com/ryankurte/go-u2f"

import "github.com/ryankurte/authplz/datastore"
import "github.com/ryankurte/authplz/token"
import "github.com/ryankurte/authplz/api"

type TestClient struct {
	*http.Client
	basePath string
}

func NewTestClient(path string) TestClient {
	jar, _ := cookiejar.New(nil)
	return TestClient{&http.Client{Jar: jar}, path}
}

func (tc *TestClient) handleErr(t *testing.T, resp *http.Response, err error, path string, statusCode int) {
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if resp.StatusCode != statusCode {
		t.Errorf("Incorrect status code from %s received: %d expected: %d", path, resp.StatusCode, statusCode)
		t.FailNow()
	}
}

func (tc *TestClient) TestGet(t *testing.T, path string, statusCode int) *http.Response {
	queryPath := tc.basePath + path

	resp, err := tc.Get(queryPath)
	tc.handleErr(t, resp, err, queryPath, statusCode)
	return resp
}

func (tc *TestClient) TestPost(t *testing.T, path string, statusCode int, v url.Values) *http.Response {
	queryPath := tc.basePath + path

	resp, err := tc.PostForm(queryPath, v)
	tc.handleErr(t, resp, err, queryPath, statusCode)
	return resp
}

func (tc *TestClient) TestGetJson(t *testing.T, path string, inst interface{}) {
	resp := tc.TestGet(t, path, http.StatusOK)
	defer resp.Body.Close()
	err := json.NewDecoder(resp.Body).Decode(&inst)
	if err != nil {
		t.Errorf("Error decoding json for type %T\n", inst)
	}
}

func (tc *TestClient) TestPostFormGetJson(t *testing.T, path string, v url.Values, responseInst interface{}) {
	
	queryPath := tc.basePath + path

	resp, err := tc.PostForm(queryPath, v)
	if err != nil {
		t.Errorf("Error %s posting to %s\n", err, queryPath)
	}

	defer resp.Body.Close()
	if resp != nil {
		err := json.NewDecoder(resp.Body).Decode(&responseInst)
		if err != nil {
			t.Errorf("Error decoding json for type %T\n", responseInst)
		}
	}
}

func (tc *TestClient) TestPostJsonGetJson(t *testing.T, path string, requestInst interface{}, responseInst interface{}) {
	
	queryPath := tc.basePath + path

	js, err := json.Marshal(requestInst)
	if err != nil {
		t.Errorf("Error %s converting %T to json\n", err, requestInst)
		return
	}

	resp, err := tc.Post(queryPath, "application/json", bytes.NewReader(js))
	if err != nil {
		t.Errorf("Error %s posting to %s\n", err, queryPath)
	}

	defer resp.Body.Close()
	if resp != nil {
		err := json.NewDecoder(resp.Body).Decode(&responseInst)
		if err != nil {
			t.Errorf("Error decoding json for type %T\n", responseInst)
		}
	}
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
	tc.TestGetJson(t, path, &status)
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
	// Setup user controller for testing
	var address string = "localhost"
	var port string = "9000"
	var dbString string = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@"

	// Attempt database connection
	server := NewServer(address, port, dbString)
	server.ds.ForceSync()

	go server.Start()
	defer server.Close()

	apiPath := "http://" + address + ":" + port + "/api"

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

		client.TestPost(t, "/create", http.StatusOK, v)

		user, _ = server.ds.GetUserByEmail(fakeEmail)
	})

	t.Run("Login fails prior to activation", func(t *testing.T) {

		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)

		client.TestPost(t, "/login", http.StatusUnauthorized, v)
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
		client2.TestPost(t, "/action", http.StatusOK, v)

		// Attempt login with activation cookie
		v = url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		client2.TestPost(t, "/login", http.StatusUnauthorized, v)

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
		client2.TestPost(t, "/action", http.StatusOK, v)

		// Attempt login with activation cookie
		v = url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		client2.TestPost(t, "/login", http.StatusOK, v)

		// Check user status
		client2.TestGetApiResponse(t, "/status", api.ApiResultOk, api.ApiMessageLoginSuccess)
	})

	t.Run("Activated users can login", func(t *testing.T) {

		// Attempt login
		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		client.TestPost(t, "/login", http.StatusOK, v)

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
			client2.TestPost(t, "/login", http.StatusUnauthorized, v)
		}

		// Check user status
		client2.TestGetApiResponse(t, "/status", api.ApiResultError, api.ApiMessageUnauthorized)

		// Set to correct password
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)

		// Check login still fails
		client2.TestPost(t, "/login", http.StatusUnauthorized, v)
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
		client2.TestPost(t, "/action", http.StatusOK, v)

		// Attempt login with activation cookie
		v = url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		client2.TestPost(t, "/login", http.StatusUnauthorized, v)

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
		client2.TestPost(t, "/action", http.StatusOK, v)

		// Attempt login with activation cookie
		v = url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		client2.TestPost(t, "/login", http.StatusOK, v)

		// Check user status
		client2.TestGetApiResponse(t, "/status", api.ApiResultOk, api.ApiMessageLoginSuccess)
	})

	t.Run("Logged in users can get account info", func(t *testing.T) {

		// Perform logout
		resp := client.TestGet(t, "/account", http.StatusOK)

		var u datastore.User
		_ = json.NewDecoder(resp.Body).Decode(&u)

		if u.Email != fakeEmail {
			t.Errorf("Email mismatch")
		}
	})

	t.Run("Logged in users can enrol tokens", func(t *testing.T) {

		// Generate enrolment request
		var rr u2f.RegisterRequestMessage
		client.TestGetJson(t, "/u2f/enrol", &rr)

		if rr.AppID != address {
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

	t.Run("Logged in users can logout", func(t *testing.T) {

		// Perform logout
		client.TestGetApiResponse(t, "/logout", api.ApiResultOk, api.ApiMessageLogoutSuccess)

		// Check user status
		client.TestGetApiResponse(t, "/status", api.ApiResultError, api.ApiMessageUnauthorized)
	})

}
