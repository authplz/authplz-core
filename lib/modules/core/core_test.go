package core

import (
	"testing"

	"time"
)

import (
	"github.com/ryankurte/authplz/lib/api"
	"github.com/ryankurte/authplz/lib/controllers/token"
)

const (
	fakeEmail string = "test@email.com"
	fakePass  string = "password123@"
)

type MockHandler struct {
	LoginCallResp        bool
	SecondFactorRequired bool
	TokenAction          api.TokenAction
	LoginAllowed         bool
	u                    interface{}
}

// user controller interface
func (mh *MockHandler) Login(email string, password string) (bool, interface{}, error) {
	var u interface{}
	return mh.LoginCallResp, u, nil
}

func (mh *MockHandler) GetUserByEmail(email string) (interface{}, error) {
	return mh.u, nil
}

// 2fa handler interface
func (mh *MockHandler) IsSupported(userid string) bool {
	return mh.SecondFactorRequired
}

// token handler interface
func (mh *MockHandler) HandleToken(u interface{}, tokenAction api.TokenAction) error {
	mh.TokenAction = tokenAction
	return nil
}

func (mh *MockHandler) PreLogin(u interface{}) (bool, error) {
	return mh.LoginAllowed, nil
}

func TestCoreModule(t *testing.T) {

	tokenControl := token.NewTokenController("localhost", "ABCD")

	mockHandler := MockHandler{false, false, api.TokenActionInvalid, false, nil}
	coreControl := NewController(tokenControl, &mockHandler)

	t.Run("Bind and call token action handlers", func(t *testing.T) {
		var u interface{}
		var mockAction api.TokenAction = "mock-action"

		coreControl.BindActionHandler("mock-action", &mockHandler)

		d, _ := time.ParseDuration("10m")
		token, _ := tokenControl.BuildToken("fakeid", mockAction, d)

		mockHandler.TokenAction = api.TokenActionInvalid
		ok, err := coreControl.HandleToken("fakeid", u, token)
		if err != nil {
			t.Error(err)
		}
		if !ok {
			t.Errorf("Token validation failed")
		}
		if mockHandler.TokenAction != mockAction {
			t.Errorf("Action handler not called (expected %+v received %+v)", mockAction, mockHandler.TokenAction)
		}
	})

	t.Run("Bind and check second factor handlers", func(t *testing.T) {
		coreControl.BindSecondFactor("mock-2fa", &mockHandler)

		mockHandler.SecondFactorRequired = false
		required, available := coreControl.CheckSecondFactors("fake")
		if required {
			t.Errorf("CheckSecondFactors expected required=false, received required=true")
		}
		if v, ok := available["mock-2fa"]; !ok || v {
			t.Errorf("Expected ok, v=false, received %b v=%b", v, ok)
		}

		mockHandler.SecondFactorRequired = true
		required, available = coreControl.CheckSecondFactors("fake")
		if !required {
			t.Errorf("CheckSecondFactors expected required=true, received required=false")
		}

		if v, ok := available["mock-2fa"]; !ok || !v {
			t.Errorf("Expected ok, v=true, received %b v=%b", v, ok)
		}
	})

	t.Run("Bind PreLogin handlers", func(t *testing.T) {
		var u interface{}

		coreControl.BindPreLogin("mock-login-handler", &mockHandler)

		mockHandler.LoginAllowed = false
		ok, err := coreControl.PreLogin(u)
		if err != nil {
			t.Error(err)
		}
		if ok {
			t.Errorf("Expected login failure")
		}

		mockHandler.LoginAllowed = true
		ok, err = coreControl.PreLogin(u)
		if err != nil {
			t.Error(err)
		}
		if !ok {
			t.Errorf("Expected login success")
		}

	})

	t.Run("Bind event handlers", func(t *testing.T) {

	})

}
