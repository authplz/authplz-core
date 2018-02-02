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
	recoveryRequestUserIDKey  = "recovery-request-userid"
)

// BindRecoveryRequest binds an authenticated recovery request to the session
// This should only be called after all [possible] authentication has been executed
func (c *AuthPlzCtx) BindRecoveryRequest(userid string, rw web.ResponseWriter, req *web.Request) {
	session, err := c.Global.SessionStore.Get(req.Request, recoveryRequestSessionKey)
	if err != nil {
		log.Printf("AuthPlzCtx.BindRecoveryRequest Error fetching %s %s", recoveryRequestSessionKey, err)
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.RecoveryNoRequestPending)
		return
	}

	session.Values[recoveryRequestUserIDKey] = userid
	session.Save(req.Request, rw)
}

// GetRecoveryRequest fetches an authenticated recovery request from the session
// This allows a module to accept new password settings for the provided user id
func (c *AuthPlzCtx) GetRecoveryRequest(rw web.ResponseWriter, req *web.Request) string {
	session, err := c.Global.SessionStore.Get(req.Request, recoveryRequestSessionKey)
	if err != nil {
		log.Printf("AuthPlzCtx.GetRecoveryRequest Error fetching %s %s", recoveryRequestSessionKey, err)
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.RecoveryNoRequestPending)
		return ""
	}

	if session.Values[recoveryRequestUserIDKey] == nil {
		return ""
	}

	return session.Values[recoveryRequestUserIDKey].(string)
}
