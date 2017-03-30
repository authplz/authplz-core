package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"github.com/ryankurte/authplz/lib/api"
)

// TestClient instance
// Handles cookies as well as API base addresses and provides convenience wrappers to simplify testing
type TestClient struct {
	*http.Client
	basePath string
}

// NewTestClient Create a new TestClient instance
func NewTestClient(path string) TestClient {
	jar, _ := cookiejar.New(nil)
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}
	return TestClient{httpClient, path}
}

// NewTestClientFromHttp Create a new TestClient instance using the provided http.Client
// Useful for OAuth clients
func NewTestClientFromHttp(path string, client *http.Client) TestClient {
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return TestClient{client, path}
}

// Get wraps client.Get with status code checks
func (tc *TestClient) Get(path string, statusCode int) (*http.Response, error) {
	queryPath := tc.basePath + path

	req, _ := http.NewRequest("GET", queryPath, nil)

	resp, err := tc.Do(req)
	if err != nil {
		return resp, err
	}

	if resp.StatusCode != statusCode {
		return resp, fmt.Errorf("Incorrect status code from '%s' received: '%d' expected: '%d'", path, resp.StatusCode, statusCode)
	}

	return resp, err
}

//GetWithParamsGet wraps client.Get with query parameters and status code checks
func (tc *TestClient) GetWithParams(path string, statusCode int, v url.Values) (*http.Response, error) {
	queryPath := tc.basePath + path

	req, _ := http.NewRequest("GET", queryPath, nil)

	req.URL.RawQuery = v.Encode()

	resp, err := tc.Do(req)
	if err != nil {
		return resp, err
	}

	if resp.StatusCode != statusCode {
		return resp, fmt.Errorf("Incorrect status code from '%s' received: '%d 'expected: '%d'", path, resp.StatusCode, statusCode)
	}

	return resp, err
}

// CheckRedirect checks that a given redirect is correct
func CheckRedirect(url string, resp *http.Response) error {
	if loc := resp.Header.Get("Location"); loc != url {
		return fmt.Errorf("Invalid location header (actual: '%s' expected: '%s'", loc, url)
	}
	return nil
}

// ParseJson assists with parsing JSON responses
func ParseJson(resp *http.Response, inst interface{}) error {
	defer resp.Body.Close()
	err := json.NewDecoder(resp.Body).Decode(&inst)
	if err != nil {
		return err
	}
	return nil
}

func (tc *TestClient) GetJSON(path string, statusCode int, inst interface{}) error {
	resp, err := tc.Get(path, statusCode)
	if err != nil {
		return err
	}

	return ParseJson(resp, inst)
}

func (tc *TestClient) GetJSONWithParams(path string, statusCode int, v url.Values, inst interface{}) error {
	resp, err := tc.GetWithParams(path, statusCode, v)
	if err != nil {
		return err
	}

	return ParseJson(resp, inst)
}

// CheckApiResponse checks an API resonse matches the provded message
func CheckApiResponse(status api.ApiResponse, result string, message string) error {
	if status.Result != result {
		return fmt.Errorf("Incorrect API result, expected: '%s' received: '%s' message: '%s'", result, status.Result, status.Message)
	}

	if message != "" && status.Message != message {
		return fmt.Errorf("Incorrect API message, expected: '%s' received: '%s'", message, status.Message)
	}

	return nil
}

func ParseAndCheckAPIResponse(resp *http.Response, result string, message string) error {
	ar := api.ApiResponse{}

	err := ParseJson(resp, &ar)
	if err != nil {
		return err
	}

	return CheckApiResponse(ar, result, message)
}

func (tc *TestClient) GetAPIResponse(path string, statusCode int, result string, message string) error {
	resp, err := tc.Get(path, statusCode)
	if err != nil {
		return err
	}

	return ParseAndCheckAPIResponse(resp, result, message)
}

// Post JSON to an api endpoint
func (tc *TestClient) PostJSON(path string, statusCode int, requestInst interface{}) (*http.Response, error) {
	queryPath := tc.basePath + path

	js, err := json.Marshal(requestInst)
	if err != nil {
		return nil, err
	}

	resp, err := tc.Post(queryPath, "application/json", bytes.NewReader(js))
	if err != nil {
		return resp, err
	}

	if resp.StatusCode != statusCode {
		return resp, fmt.Errorf("Incorrect status code from %s received: %d expected: %d", path, resp.StatusCode, statusCode)
	}

	return resp, nil
}

// PostForm Post a form to an api endpoint
func (tc *TestClient) PostForm(path string, statusCode int, v url.Values) (*http.Response, error) {
	queryPath := tc.basePath + path

	resp, err := tc.Client.PostForm(queryPath, v)
	if err != nil {
		return resp, err
	}

	if resp.StatusCode != statusCode {
		return resp, fmt.Errorf("Incorrect status code from %s received: %d expected: %d", path, resp.StatusCode, statusCode)
	}

	return resp, nil
}
