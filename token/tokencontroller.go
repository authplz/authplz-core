package token

import "time"
import "fmt"

import "github.com/dgrijalva/jwt-go"
import "github.com/satori/go.uuid"

// Custom claims object
type TokenClaims struct {
	Action string `json:"act"` // Token action
	jwt.StandardClaims
}

const TokenActionActivate string = "activate"
const TokenActionUnlock string = "unlock"

// User object
type TokenController struct {
	address    string
	hmacSecret []byte
}

var signingMethod jwt.SigningMethod = jwt.SigningMethodHS256

func NewTokenController(address string, hmacSecret string) TokenController {
	return TokenController{address: address, hmacSecret: []byte(hmacSecret)}
}

func (tc *TokenController) BuildToken(userid string, action string, duration time.Duration) (string, error) {

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
