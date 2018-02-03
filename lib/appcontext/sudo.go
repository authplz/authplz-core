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

const (
	// SudoSessionKey is the cookie key used for sudo session storage
	sudoSessionKey = "sudo-session"
	// Timeout for sudo sessions
	sudoTimeout = 60 * 10 // 10 minutes
)

// SudoSession used to store user reauthorization sessions for protected account actions
// Such as password changes or 2fa alterations
type SudoSession struct {
	UserID       string
	SessionStart time.Time
	SessionEnd   time.Time
}

// SetSudo used to indicate a user has reauthorized to allow protected account actions
// TODO: could this be pinned to more things? (user agent, IP, real invalidation so it can't be reused if cancelled?)
// Guess re-use is a bit moot given there is no reason to cancel atm
func (c *AuthPlzCtx) SetSudo(userID string, timeout time.Duration, rw web.ResponseWriter, req *web.Request) {
	log.Printf("AuthPlzCtx.SetSudo: creating sudo session fo user %s", c.userid)

	session, err := c.GetNamedSession(rw, req, sudoSessionKey)
	if err != nil {
		c.WriteInternalError(rw)
		return
	}

	sudoSession := SudoSession{
		UserID:       userID,
		SessionStart: time.Now(),
		SessionEnd:   time.Now().Add(timeout),
	}

	session.Values[sudoSessionKey] = sudoSession
	session.Options.MaxAge = sudoTimeout
	session.Save(req.Request, rw)
}

// ClearSudo removes a sudo session from a user session
func (c *AuthPlzCtx) ClearSudo(rw web.ResponseWriter, req *web.Request) {
	log.Printf("AuthPlzCtx.ClearSudo: ending sudo session fo user %s", c.userid)

	session, err := c.GetNamedSession(rw, req, sudoSessionKey)
	if err != nil {
		c.WriteInternalError(rw)
		return
	}

	session.Options.MaxAge = -1
	session.Save(req.Request, rw)
}

// CanSudo checks whether a user has a current sudo session
func (c *AuthPlzCtx) CanSudo(rw web.ResponseWriter, req *web.Request) bool {
	session, err := c.GetNamedSession(rw, req, sudoSessionKey)
	if err != nil {
		c.WriteInternalError(rw)
		return false
	}
	s := session.Values[sudoSessionKey]
	if s == nil {
		return false
	}
	sudoSession, ok := s.(SudoSession)
	if !ok {
		c.ClearSudo(rw, req)
		return false
	}
	if time.Now().Before(sudoSession.SessionStart) {
		c.ClearSudo(rw, req)
		return false
	}
	if time.Now().After(sudoSession.SessionEnd) {
		c.ClearSudo(rw, req)
		return false
	}
	if sudoSession.UserID != c.GetUserID() {
		c.ClearSudo(rw, req)
		return false
	}
	return true
}
