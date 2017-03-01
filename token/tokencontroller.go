// Implements JWT token building and parsing
// This is used for actions such as user activation, login, account unlock.

package token

import (
	"encoding/gob"
	"fmt"
	"log"
	"time"
)

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/ryankurte/authplz/api"
	"github.com/satori/go.uuid"
)

// Custom claims object
type TokenClaims struct {
	Action api.TokenAction `json:"act"` // Token action
	jwt.StandardClaims
}

// TokenController instance
type TokenController struct {
	address    string
	hmacSecret []byte
}

// Default signing method
var signingMethod jwt.SigningMethod = jwt.SigningMethodHS256

func init() {
	gob.Register(&TokenClaims{})
}

//TokenController constructor
func NewTokenController(address string, hmacSecret string) *TokenController {
	return &TokenController{address: address, hmacSecret: []byte(hmacSecret)}
}

// Generate an action token
func (tc *TokenController) BuildToken(userid string, action api.TokenAction, duration time.Duration) (string, error) {

	claims := TokenClaims{
		Action: action,
		StandardClaims: jwt.StandardClaims{
			Id:        uuid.NewV4().String(),
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(duration).Unix(),
			Subject:   userid,
			Issuer:    tc.address,
		},
	}

	token := jwt.NewWithClaims(signingMethod, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(tc.hmacSecret)

	return tokenString, err
}

// Parse and validate an action token
func (tc *TokenController) ParseToken(tokenString string) (*TokenClaims, error) {

	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate algorithm is correct
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// Return secret
		return tc.hmacSecret, nil
	})

	claims, ok := token.Claims.(*TokenClaims)
	if ok && token.Valid {
		return claims, nil
	} else {
		fmt.Println(err)
		return nil, err
	}
}

func (tc *TokenController) ValidateToken(userId, tokenString string) (*api.TokenAction, error) {
	// Parse token
	claims, err := tc.ParseToken(tokenString)
	if err != nil {
		log.Println("TokenController.ValidateToken: Invalid or expired token (%s)", err)
		return nil, err
	}

	// Check subject matches
	if claims.Subject != userId {
		log.Println("TokenController.ValidateToken: Subject ID mismatch")
		return nil, api.TokenErrorInvalidUser
	}

	// Return claim
	return &claims.Action, nil
}
