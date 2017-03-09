package test

import "testing"

//import "fmt"

import (
	"bytes"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"encoding/json"
)

import (
	"github.com/ryankurte/authplz/api"
)

// Test client instance
// Handles cookies as well as API base addresses to simplify testing
// Signifies failure using the bound testing class.
type TestClient struct {
	*http.Client
	basePath string
	t        *testing.T
}

// Test response instance
// Allows chaining of requests and responses
type TestResponse struct {
	*http.Response
	Error error
	t     *testing.T
}

// Create a new TestClient instance
func NewTestClient(path string) TestClient {
	jar, _ := cookiejar.New(nil)
	return TestClient{&http.Client{Jar: jar}, path, nil}
}

func NewTestClientFromHttp(path string, client *http.Client) TestClient {
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	return TestClient{client, path, nil}
}

// Bind a testing instance to a test client
func (tc *TestClient) BindTest(t *testing.T) *TestClient {
	tc.t = t

	return tc
}

// Internal helper to handle errors
func (tc *TestClient) testHandleErr(resp *http.Response, err error, path string, statusCode int) {
	if err != nil {
		tc.t.Error(err)
		tc.t.FailNow()
	}
	if resp.StatusCode != statusCode {
		tc.t.Errorf("Incorrect status code from %s received: %d expected: %d", path, resp.StatusCode, statusCode)
		tc.t.FailNow()
	}
}

// Get from an API endpoint
func (tc *TestClient) TestGet(path string, statusCode int) *TestResponse {
	queryPath := tc.basePath + path

	resp, err := tc.Get(queryPath)
	tc.testHandleErr(resp, err, queryPath, statusCode)

	tr := &TestResponse{resp, err, tc.t}

	return tr
}

func (tc *TestClient) TestGetWithParams(path string, statusCode int, v url.Values) *TestResponse {
	queryPath := tc.basePath + path

	req, _ := http.NewRequest("GET", queryPath, nil)

	req.URL.RawQuery = v.Encode()

	resp, err := tc.Do(req)
	tc.testHandleErr(resp, err, queryPath, statusCode)

	tr := &TestResponse{resp, err, tc.t}

	return tr
}

// Post a form to an api endpoint
func (tc *TestClient) TestPostForm(path string, statusCode int, v url.Values) *TestResponse {
	queryPath := tc.basePath + path

	resp, err := tc.PostForm(queryPath, v)
	tc.testHandleErr(resp, err, queryPath, statusCode)

	tr := &TestResponse{resp, err, tc.t}

	return tr
}

// Post JSON to an api endpoint
func (tc *TestClient) TestPostJson(path string, statusCode int, requestInst interface{}) *TestResponse {

	queryPath := tc.basePath + path

	js, err := json.Marshal(requestInst)
	if err != nil {
		tc.t.Errorf("Error %s converting %T to json\n", err, requestInst)
		return nil
	}

	resp, err := tc.Post(queryPath, "application/json", bytes.NewReader(js))
	tc.testHandleErr(resp, err, queryPath, statusCode)

	tr := &TestResponse{resp, err, tc.t}

	return tr
}

// Parse a response to JSON
func (tc *TestResponse) TestParseJson(inst interface{}) interface{} {
	defer tc.Body.Close()
	if tc.Error == nil {
		err := json.NewDecoder(tc.Body).Decode(&inst)
		if err != nil {
			tc.t.Errorf("Error decoding json for type %T\n", inst)
		}
	}
	return inst
}

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
