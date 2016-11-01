package app

import "testing"

//import "fmt"

import "bytes"
import "net/http"
import "net/url"
import "net/http/cookiejar"

import "encoding/json"

// Test client instance
// Handles cookies as well as API base addresses to simplify testing
// Signifies failure using the bound testing class.
type TestClient struct {
    *http.Client
    basePath string
    t *testing.T
}

// Test response instance
// Allows chaining of requests and responses
type TestResponse struct {
    *http.Response
    Error error
    t *testing.T
}

// Create a new TestClient instance
func NewTestClient(path string) TestClient {
    jar, _ := cookiejar.New(nil)
    return TestClient{&http.Client{Jar: jar}, path, nil}
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

