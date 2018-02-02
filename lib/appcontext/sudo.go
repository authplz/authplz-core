/* AuthPlz Authentication and Authorization Microservice
 * Application context "sudo" implementation (WIP)
 *
 * Copyright 2018 Ryan Kurte
 */

package appcontext

import (
	"log"
	"time"

	"github.com/gocraft/web"
)

// SudoSession used to store user reauthorization sessions for protected account actions
// Such as password changes or 2fa alterations
type SudoSession struct {
	UserID       string
	SessionStart time.Time
	SessionEnd   time.Time
}

// SudoSessionKey is the cookie key used for sudo session storage
const sudoSessionKey = "sudo-session"

// SetSudo used to indicate a user has reauthorized to allow protected account actions
// TODO: could this be pinned to more things? (user agent, IP, real invalidation so it can't be reused if cancelled?)
// Guess re-use is a bit moot given there is no reason to cancel atm
func (c *AuthPlzCtx) SetSudo(userID string, timeout time.Duration, rw web.ResponseWriter, req *web.Request) {
	log.Printf("AuthPlzCtx.SetSudo: creating sudo session fo user %s", c.userid)

	sudoSession := SudoSession{
		UserID:       userID,
		SessionStart: time.Now(),
		SessionEnd:   time.Now().Add(timeout),
	}

	c.session.Values[sudoSessionKey] = sudoSession
	c.session.Save(req.Request, rw)
}

// ClearSudo removes a sudo session from a user session
func (c *AuthPlzCtx) ClearSudo(rw web.ResponseWriter, req *web.Request) {
	c.session.Values[sudoSessionKey] = nil
	c.session.Save(req.Request, rw)
}

// CanSudo checks whether a user has a current sudo session
func (c *AuthPlzCtx) CanSudo(rw web.ResponseWriter, req *web.Request) bool {
	sudoSession := c.session.Values[sudoSessionKey]
	if sudoSession == nil {
		return false
	}
	session, ok := sudoSession.(SudoSession)
	if !ok {
		c.ClearSudo(rw, req)
		return false
	}
	if time.Now().Before(session.SessionStart) {
		c.ClearSudo(rw, req)
		return false
	}
	if time.Now().After(session.SessionEnd) {
		c.ClearSudo(rw, req)
		return false
	}
	if session.UserID != c.GetUserID() {
		c.ClearSudo(rw, req)
		return false
	}
	return true
}
