// Implements JWT token building and parsing
// This is used for actions such as user activation, login, account unlock.

package token

import (
	"encoding/gob"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/satori/go.uuid"

	"github.com/authplz/authplz-core/lib/api"
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
	storer     Storer
}

// Default signing method
var signingMethod jwt.SigningMethod = jwt.SigningMethodHS256

func init() {
	gob.Register(&TokenClaims{})
}

//NewTokenController constructor
func NewTokenController(address string, hmacSecret string, storer Storer) *TokenController {
	return &TokenController{address: address, hmacSecret: []byte(hmacSecret), storer: storer}
}

// Generate an action token
func (tc *TokenController) buildSignedToken(userID, tokenID string, action api.TokenAction, duration time.Duration) (string, error) {

	claims := TokenClaims{
		Action: action,
		StandardClaims: jwt.StandardClaims{
			Id:        tokenID,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(duration).Unix(),
			Subject:   userID,
			Issuer:    tc.address,
		},
	}

	token := jwt.NewWithClaims(signingMethod, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(tc.hmacSecret)

	return tokenString, err
}

// BuildToken builds a signed token for the given user id with a provided action and duration for use
func (tc *TokenController) BuildToken(userID string, action api.TokenAction, duration time.Duration) (string, error) {

	tokenID := uuid.NewV4().String()

	_, err := tc.storer.CreateActionToken(userID, tokenID, string(action), time.Now().Add(duration))
	if err != nil {
		return "", err
	}

	signedToken, err := tc.buildSignedToken(userID, tokenID, action, duration)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// Parse and validate an action token
func (tc *TokenController) parseToken(tokenString string) (*TokenClaims, error) {

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

// ValidateToken validates a token using the provided key and backing store
func (tc *TokenController) ValidateToken(userID, tokenString string) (*api.TokenAction, error) {
	// Parse token
	claims, err := tc.parseToken(tokenString)
	if err != nil {
		log.Printf("TokenController.ValidateToken: Invalid or expired token (%s)", err)
		return nil, err
	}

	// Check subject matches
	if claims.Subject != userID {
		log.Println("TokenController.ValidateToken: Subject ID mismatch")
		return nil, api.TokenErrorInvalidUser
	}

	// Fetch from backing db
	t, err := tc.storer.GetActionToken(claims.Id)
	if err != nil {
		log.Println("TokenController.ValidateToken: No matching token found in datastore")
		return nil, api.TokenErrorNotFound
	}
	token := t.(Token)

	// Check components match
	if token.GetUserExtID() != claims.Subject {
		log.Println("TokenController.ValidateToken: Token subject mismatch")
		return nil, api.TokenErrorInvalidUser
	}
	if token.GetAction() != string(claims.Action) {
		log.Println("TokenController.ValidateToken: Token action mismatch")
		return nil, api.TokenErrorInvalidAction
	}
	if token.IsUsed() {
		log.Println("TokenController.ValidateToken: Token already used")
		return nil, api.TokenErrorAlreadyUsed
	}

	// Return claim
	return &claims.Action, nil
}

// SetUsed marks a token as used in the backing datastore
func (tc *TokenController) SetUsed(tokenString string) error {
	// Parse and validate
	claims, err := tc.parseToken(tokenString)
	if err != nil {
		log.Printf("TokenController.ValidateToken: Invalid or expired token (%s)", err)
		return err
	}

	// Fetch from backing db
	t, err := tc.storer.GetActionToken(claims.Id)
	if err != nil {
		return err
	}
	token := t.(Token)

	token.SetUsed(time.Now())

	_, err = tc.storer.UpdateActionToken(token)

	return err
}
