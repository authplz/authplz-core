package token

import "testing"
import "time"
import "fmt"

import "github.com/satori/go.uuid"

func TestTokenController(t *testing.T) {

	var fakeHmacKey string = "01234567890123456789012345678901"
	var fakeAddress string = "localhost"

	tc := NewTokenController(fakeAddress, fakeHmacKey)

	var fakeUuid = uuid.NewV4().String()
	var tokenString string

	// Run tests
	t.Run("Generates tokens", func(t *testing.T) {
		d, _ := time.ParseDuration("10m")
		token, err := tc.BuildToken(fakeUuid, "activate", d)
		if err != nil {
			t.Error(err)
		}
		if len(token) == 0 {
			t.Error("Token creation failed")
		}
		tokenString = token
	})

	t.Run("Parses tokens", func(t *testing.T) {
		claims, err := tc.ParseToken(tokenString)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		if claims == nil {
			t.Error("Token returned no claims")
			t.FailNow()
		}
		fmt.Println(claims)
		if (claims.Action != "activate") || (claims.StandardClaims.Subject != fakeUuid) {
			t.Error("Mismatched claims & subject")
		}
	})

	t.Run("Rejects invalid token signatures", func(t *testing.T) {
		brokenToken := []byte(tokenString[0 : len(tokenString)-1])
		brokenToken[len(brokenToken)-1] = brokenToken[len(brokenToken)-1] - 1
		brokenString := string(brokenToken)

		_, err := tc.ParseToken(brokenString)
		if err == nil {
			t.Error("Invalid token should cause error")
			t.FailNow()
		}
	})

	t.Run("Rejects expired tokens", func(t *testing.T) {
		d, _ := time.ParseDuration("-10m")
		token, err := tc.BuildToken(fakeUuid, "activate", d)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		_, err = tc.ParseToken(token)
		if err == nil {
			t.Error("Expired token should cause error")
			t.FailNow()
		}
	})

}
