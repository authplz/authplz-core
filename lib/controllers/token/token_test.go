package token

import (
	"fmt"
	"testing"
	"time"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"

	"github.com/ryankurte/authplz/lib/api"
	"github.com/ryankurte/authplz/lib/controllers/datastore"
)

type FakeActionTokenStore struct {
	tokens map[string]datastore.ActionToken
}

func NewFakeActionTokenStore() *FakeActionTokenStore {
	return &FakeActionTokenStore{
		tokens: make(map[string]datastore.ActionToken),
	}
}

func (f *FakeActionTokenStore) CreateActionToken(userID, tokenID, action string, expiry time.Time) (interface{}, error) {
	t := datastore.ActionToken{
		TokenID:   tokenID,
		UserExtID: userID,
		Action:    action,
		ExpiresAt: expiry,
		Used:      false,
	}

	f.tokens[tokenID] = t

	return &t, nil
}

func (f *FakeActionTokenStore) GetActionToken(tokenID string) (interface{}, error) {
	t, ok := f.tokens[tokenID]
	if !ok {
		return nil, fmt.Errorf("No matching token found")
	}
	return &t, nil
}

func (f *FakeActionTokenStore) UpdateActionToken(t interface{}) (interface{}, error) {
	token := t.(*datastore.ActionToken)

	f.tokens[token.TokenID] = *token

	return token, nil
}

func TestTokenController(t *testing.T) {

	var fakeHmacKey string = "01234567890123456789012345678901"
	var fakeAddress string = "localhost"

	fakeStore := NewFakeActionTokenStore()

	tc := NewTokenController(fakeAddress, fakeHmacKey, fakeStore)

	var fakeUserExtID = uuid.NewV4().String()
	var tokenString string

	// Run tests
	t.Run("Generates tokens", func(t *testing.T) {
		d, _ := time.ParseDuration("10m")
		token, err := tc.BuildToken(fakeUserExtID, "activate", d)
		assert.Nil(t, err)
		if len(token) == 0 {
			t.Error("Token creation failed")
		}
		tokenString = token
	})

	t.Run("Parses tokens", func(t *testing.T) {
		claims, err := tc.parseToken(tokenString)
		assert.Nil(t, err)
		if claims == nil {
			t.Error("Token returned no claims")
			t.FailNow()
		}
		fmt.Println(claims)
		if (claims.Action != "activate") || (claims.StandardClaims.Subject != fakeUserExtID) {
			t.Error("Mismatched claims & subject")
		}
	})

	t.Run("Validates tokens", func(t *testing.T) {
		action, err := tc.ValidateToken(fakeUserExtID, tokenString)
		assert.Nil(t, err)
		assert.EqualValues(t, api.TokenActionActivate, *action)
	})

	t.Run("Rejects invalid token signatures", func(t *testing.T) {
		brokenToken := []byte(tokenString[0 : len(tokenString)-1])
		brokenToken[len(brokenToken)-1] = brokenToken[len(brokenToken)-1] - 1
		brokenString := string(brokenToken)

		_, err := tc.parseToken(brokenString)
		if err == nil {
			t.Error("Invalid token should cause error")
			t.FailNow()
		}
	})

	t.Run("Rejects expired tokens", func(t *testing.T) {
		d, _ := time.ParseDuration("-10m")
		token, err := tc.BuildToken(fakeUserExtID, "activate", d)
		assert.Nil(t, err)

		_, err = tc.parseToken(token)
		if err == nil {
			t.Error("Expired token should cause error")
			t.FailNow()
		}
	})

	t.Run("Tokens can only be used once", func(t *testing.T) {
		_, err := tc.ValidateToken(fakeUserExtID, tokenString)
		assert.Nil(t, err, "Expected token validation to succeed")

		tc.SetUsed(tokenString)

		_, err = tc.ValidateToken(fakeUserExtID, tokenString)
		assert.EqualValues(t, api.TokenErrorAlreadyUsed, err, "Expected token validation to be blocked")
	})

}
