package token

import "time"
import "fmt"

import "github.com/dgrijalva/jwt-go"

// Custom claims object
type TokenClaims struct {
	Action string `json:"act"` // Token action
	jwt.StandardClaims
}

type TokenAction string

//const {
//	TokenActionActivate = "activate"
//	TokenActionUnblock  = "unblock"
//}

// User object
type TokenController struct {
	hmacSecret []byte
}

var signingMethod jwt.SigningMethod = jwt.SigningMethodHS256

func NewTokenController(hmacSecret string) *TokenController {
	return &TokenController{hmacSecret: []byte(hmacSecret)}
}

func (tc *TokenController) BuildToken(uuid string, action string, duration time.Duration) (string, error) {

	claims := TokenClaims{
		Action: action,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(duration).Unix(),
			Subject:   uuid,
			Issuer:    "test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

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
		fmt.Printf("%v %v", claims.Action, claims.StandardClaims.ExpiresAt)
		return claims, nil
	} else {
		fmt.Println(err)
		return nil, err
	}
}
