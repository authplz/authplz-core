package appcontext

import (
	"log"

	"github.com/gocraft/web"
	"github.com/ryankurte/authplz/api"
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
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
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
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return ""
	}

	if session.Values[recoveryRequestUserIDKey] == nil {
		return ""
	}

	return session.Values[recoveryRequestUserIDKey].(string)
}
