package main

import "testing"

import "net/http"
import "net/url"

type TestClient struct {
	*http.Client
	basePath string
}

func NewTestClient(path string) (TestClient) {
	return TestClient{&http.Client{}, path}
}

func (tc* TestClient) handleErr(t *testing.T, resp *http.Response, err error, path string, statusCode int) {
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if resp.StatusCode != statusCode {
		t.Errorf("Incorrect status code from %s received: %d expected: %d", path, resp.StatusCode, statusCode)
		t.FailNow()
	}
}

func (tc* TestClient) TestGet(t *testing.T, path string, statusCode int) *http.Response {
	queryPath := tc.basePath + path;

	resp, err := tc.Get(queryPath)
	tc.handleErr(t, resp, err, queryPath, statusCode)
	return resp
}

func (tc* TestClient) TestPost(t *testing.T, path string, statusCode int, v url.Values) *http.Response {
	queryPath := tc.basePath + path;

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

	go server.Start();
	defer server.Close();

	client := NewTestClient("http://" + address + ":" + port + "/api");

	// Run tests
	t.Run("Login status", func(t *testing.T) {
		client.TestGet(t, "/status", http.StatusUnauthorized)
	})

	t.Run("Create User", func(t *testing.T) {
		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("pass", fakePass)

		client.TestPost(t, "/create", http.StatusOK, v)
	})

}
