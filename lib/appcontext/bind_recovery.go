/* AuthPlz Authentication and Authorization Microservice
 * Application context handlers for recovery sessions
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

const (
	recoveryRequestSessionKey = "recovery-request-session"
	recoveryRequestUserIDKey  = "recovery-request-userID"
	recoveryRequestExpiry     = 60 * 10
)

// BindRecoveryRequest binds an authenticated recovery request to the session
// This should only be called after all [possible] authentication has been executed
func (c *AuthPlzCtx) BindRecoveryRequest(userID string, rw web.ResponseWriter, req *web.Request) {
	log.Printf("AuthPlzCtx.BindRecoveryRequest adding recovery request session for user %s\n", userID)

	session, err := c.GetNamedSession(rw, req, recoveryRequestSessionKey)
	if err != nil {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.RecoveryNoRequestPending)
		return
	}

	session.Values[recoveryRequestUserIDKey] = userID
	session.Options.MaxAge = recoveryRequestExpiry
	session.Save(req.Request, rw)
}

// GetRecoveryRequest fetches an authenticated recovery request from the session
// This allows a module to accept new password settings for the provided user id
func (c *AuthPlzCtx) GetRecoveryRequest(rw web.ResponseWriter, req *web.Request) string {
	session, err := c.GetNamedSession(rw, req, recoveryRequestSessionKey)
	if err != nil {
		log.Printf("AuthPlzCtx.GetRecoveryRequest No recovery request session found")
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.RecoveryNoRequestPending)
		return ""
	}

	userID := session.Values[recoveryRequestUserIDKey]
	if userID == nil {
		log.Printf("AuthPlzCtx.GetRecoveryRequest No recovery request session found")
		return ""
	}

	session.Options.MaxAge = -1
	session.Save(req.Request, rw)

	return userID.(string)
}
