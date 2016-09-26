package token

import "time"

import "github.com/dgrijalva/jwt-go"

// User object
type TokenController struct {
    hmacSecret string
}

var signingMethod jwt.SigningMethod = jwt.SigningMethodHS256;

func NewTokenController(hmacSecret string) (*TokenController) {
    return &TokenController{hmacSecret: hmacSecret}
}

func (tc *TokenController) BuildToken(uuid string, action string, duration time.Duration) (*string, error) {

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "sub": "bar",
        "act": "action",
        "iss": time.Now().Unix(),
        "exp": time.Now().Add(duration).Unix(),
    })

    // Sign and get the complete encoded token as a string using the secret
    tokenString, err := token.SignedString(tc.hmacSecret)

    return &tokenString, err;
}
