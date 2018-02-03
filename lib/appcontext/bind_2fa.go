/* AuthPlz Authentication and Authorization Microservice
 * Context helpers for second factor authentication
 *
 * Copyright 2018 Ryan Kurte
 */

package appcontext

import (
	"log"
	"net/http"

	"github.com/authplz/authplz-core/lib/api"
	"github.com/gocraft/web"
)

// SecondFactorRequest is a request for 2fa
// This is used to register a request that can be fetched by 2fa implementations
type SecondFactorRequest struct {
	UserID string
	Action string
}

const (
	secondFactorRequestSessionKey = "2fa-request-session"
	secondFactorUserIDKey         = "2fa-user-id"
	secondFactorActionKey         = "2fa-action"

	secondFactorTimeout = 60 * 10
)

// Bind2FARequest Bind a 2fa request and action for a user
func (c *AuthPlzCtx) Bind2FARequest(rw web.ResponseWriter, req *web.Request, userID string, action string) {
	log.Printf("AuthPlzCtx.Bind2faRequest adding 2fa request session for user %s\n", userID)

	session, err := c.GetNamedSession(rw, req, secondFactorRequestSessionKey)
	if err != nil {
		c.WriteInternalError(rw)
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorNoRequestSession)
		return
	}

	session.Values[secondFactorUserIDKey] = userID
	session.Values[secondFactorActionKey] = action
	session.Options.MaxAge = secondFactorTimeout

	session.Save(req.Request, rw)
}

// Get2FARequest Fetch a 2fa request and action for a user
func (c *AuthPlzCtx) Get2FARequest(rw web.ResponseWriter, req *web.Request) (string, string) {
	session, err := c.GetNamedSession(rw, req, secondFactorRequestSessionKey)
	if err != nil {
		log.Printf("AuthPlzCtx.Get2FARequest No 2fa request session found")
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorNoRequestSession)
		return "", ""
	}

	userID, ok1 := session.Values[secondFactorUserIDKey]
	action, ok2 := session.Values[secondFactorActionKey]

	if !ok1 || !ok2 {
		log.Printf("AuthPlzCtx.Get2FARequest No 2fa request session found")
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorNoRequestSession)
		return "", ""
	}

	session.Options.MaxAge = -1
	session.Save(req.Request, rw)

	return userID.(string), action.(string)
}
