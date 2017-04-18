package appcontext

import (
	"log"

	"github.com/gocraft/web"
	"github.com/ryankurte/authplz/lib/api"
)

// SecondFactorRequest is a request for 2fa
// This is used to register a request that can be fetched by 2fa implementations
type SecondFactorRequest struct {
	UserID string
	Action string
}

const (
	secondFactorRequestSessionKey = "2fa-request-session"
)

// Bind2FARequest Bind a 2fa request and action for a user
// TODO: the request should probably time-out eventually
func (c *AuthPlzCtx) Bind2FARequest(rw web.ResponseWriter, req *web.Request, userID string, action string) {
	log.Printf("AuthPlzCtx.Bind2faRequest adding 2fa request session for user %s\n", userID)

	secondFactorRequest := SecondFactorRequest{
		UserID: userID,
		Action: action,
	}

	c.session.Values[secondFactorRequestSessionKey] = secondFactorRequest
	c.session.Save(req.Request, rw)
}

// Get2FARequest Fetch a 2fa request and action for a user
func (c *AuthPlzCtx) Get2FARequest(rw web.ResponseWriter, req *web.Request) (string, string) {
	request := c.session.Values[secondFactorRequestSessionKey]

	if request == nil {
		c.WriteApiResult(rw, api.ResultError, "No 2fa request session")
		log.Printf("AuthPlzCtx.Get2FARequest No 2fa request session found in session flash")
		return "", ""
	}

	secondFactorRequest, ok := c.session.Values[secondFactorRequestSessionKey].(SecondFactorRequest)
	if !ok {
		c.WriteApiResult(rw, api.ResultError, "Invalid 2fa request session")
		log.Printf("AuthPlzCtx.Get2FARequest No 2fa request session found in session flash")
	}

	return secondFactorRequest.UserID, secondFactorRequest.Action
}
