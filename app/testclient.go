package app

import "testing"

//import "fmt"

import "bytes"
import "net/http"
import "net/url"
import "net/http/cookiejar"

import "encoding/json"


type TestClient struct {
    *http.Client
    basePath string
    resp *http.Response
}

// Create a new TestClient instance
func NewTestClient(path string) TestClient {
    jar, _ := cookiejar.New(nil)
    return TestClient{&http.Client{Jar: jar}, path, nil}
}

// Internal helper to handle errors
func (tc *TestClient) testHandleErr(t *testing.T, resp *http.Response, err error, path string, statusCode int) {
    if err != nil {
        t.Error(err)
        t.FailNow()
    }
    if resp.StatusCode != statusCode {
        t.Errorf("Incorrect status code from %s received: %d expected: %d", path, resp.StatusCode, statusCode)
        t.FailNow()
    }
}

func (tc *TestClient) TestGet(t *testing.T, path string, statusCode int) *TestClient {
    queryPath := tc.basePath + path

    resp, err := tc.Get(queryPath)
    tc.testHandleErr(t, resp, err, queryPath, statusCode)
    tc.resp = resp
    return tc
}

func (tc *TestClient) TestPostForm(t *testing.T, path string, statusCode int, v url.Values) *TestClient {
    queryPath := tc.basePath + path

    resp, err := tc.PostForm(queryPath, v)
    tc.testHandleErr(t, resp, err, queryPath, statusCode)
    tc.resp = resp
    return tc
}

func (tc *TestClient) TestPostJson(t *testing.T, path string, statusCode int, requestInst interface{}) *TestClient {

    queryPath := tc.basePath + path

    js, err := json.Marshal(requestInst)
    if err != nil {
        t.Errorf("Error %s converting %T to json\n", err, requestInst)
        return nil
    }

    resp, err := tc.Post(queryPath, "application/json", bytes.NewReader(js))
    tc.testHandleErr(t, resp, err, queryPath, statusCode)

    tc.resp = resp
    return tc
}

func (tc *TestClient) TestParseJson(t *testing.T, inst interface{}) {
    defer tc.resp.Body.Close()
    if tc.resp != nil {
        err := json.NewDecoder(tc.resp.Body).Decode(&inst)
        if err != nil {
            t.Errorf("Error decoding json for type %T\n", inst)
        }
    }
}

