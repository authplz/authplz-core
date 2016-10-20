package main

import "testing"

import "time"
import "net/http"
import "net/url"
import "net/http/cookiejar"

import "github.com/ryankurte/authplz/datastore"
import "github.com/ryankurte/authplz/token"

type TestClient struct {
	*http.Client
	basePath string
}

func NewTestClient(path string) TestClient {
	jar, _ := cookiejar.New(nil);
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

	client := NewTestClient("http://" + address + ":" + port + "/api")
	var user *datastore.User

	// Run tests
	t.Run("Login status", func(t *testing.T) {
		client.TestGet(t, "/status", http.StatusUnauthorized)
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

	t.Run("Accounts can be activated", func(t *testing.T) {

		d, _ := time.ParseDuration("10m")
		at, _ := server.ctx.tokenController.BuildToken(user.UUID, token.TokenActionActivate, d)

		v := url.Values{}
		v.Set("token", at)
		client.TestPost(t, "/action", http.StatusOK, v)

		v = url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)

		client.TestPost(t, "/login", http.StatusOK, v)

		t.FailNow()
	})

}
