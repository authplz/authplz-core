/* AuthPlz Authentication and Authorization Microservice
 * Core application context
 * This base context is available on all endpoints
 *
 * Copyright 2018 Ryan Kurte
 */

package appcontext

import (
	"encoding/gob"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/gocraft/web"
	"github.com/gorilla/sessions"
	//"github.com/authplz/authplz-core/lib/api"
)

func init() {
	gob.Register(SudoSession{})
	gob.Register(SecondFactorRequest{})
}

// AuthPlzGlobalCtx Application global / static context
type AuthPlzGlobalCtx struct {
	SessionStore *sessions.CookieStore
}

// NewGlobalCtx creates a new global context instance
func NewGlobalCtx(sessionStore *sessions.CookieStore) AuthPlzGlobalCtx {
	return AuthPlzGlobalCtx{sessionStore}
}

// AuthPlzCtx is the common per-request context
// Modules implement their own contexts that extend this as a base
type AuthPlzCtx struct {
	Global       *AuthPlzGlobalCtx
	session      *sessions.Session
	userid       string
	message      string
	remoteAddr   string
	forwardedFor string
	locale       string
}

// User is the user instance interface used in the app context
type User interface {
	GetExtID() string
	IsAdmin() string
}

// MiddlewareFunc Convenience type to describe middleware functions
type MiddlewareFunc func(c *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc)

// BindContext Helper to bind the global context object into the router context
// This is a closure to run over an instance of the global context
func BindContext(globalCtx *AuthPlzGlobalCtx) MiddlewareFunc {
	return func(ctx *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.Global = globalCtx
		next(rw, req)
	}
}

// GetSession fetches the base user session instance
// Modules can use this base session or their own session instances
func (c *AuthPlzCtx) GetSession() *sessions.Session {
	return c.session
}

// SessionMiddleware User session layer
// Middleware matches user session if it exists and saves userid to the session object
func (c *AuthPlzCtx) SessionMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	session, _ := c.Global.SessionStore.Get(req.Request, "user-session")

	// Save session for further use
	c.session = session

	// TODO: load user from session

	session.Save(req.Request, rw)
	next(rw, req)
}

// GetIPMiddleware Middleware to grab IP & forwarding headers and store in session
func (c *AuthPlzCtx) GetIPMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	c.remoteAddr, _, _ = net.SplitHostPort(req.RemoteAddr)
	c.forwardedFor = req.Header.Get("x-forwarded-for")

	next(rw, req)
}

// RequireAccountMiddleware to ensure only logged in access to an endpoint
func (c *AuthPlzCtx) RequireAccountMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	if c.userid == "" {
		c.WriteUnauthorized(rw)
	} else {
		next(rw, req)
	}
}

// LoginUser Helper function to login a user
func (c *AuthPlzCtx) LoginUser(userid string, rw web.ResponseWriter, req *web.Request) {
	if c.session == nil {
		log.Printf("Error logging in user, no session found")
		return
	}

	c.session.Values["userId"] = userid
	c.session.Save(req.Request, rw)
	c.userid = userid
	log.Printf("Context: logged in user %s", userid)
}

// LogoutUser Helper function to logout a user
func (c *AuthPlzCtx) LogoutUser(rw web.ResponseWriter, req *web.Request) {
	log.Printf("Context: logging out user %s", c.userid)
	c.session.Options.MaxAge = -1
	c.session.Save(req.Request, rw)
	c.userid = ""
}

// GetUserID Fetch user id from a session
// Blank if a user is not logged in
func (c *AuthPlzCtx) GetUserID() string {
	id := c.session.Values["userId"]
	if id != nil {
		return id.(string)
	} else {
		return ""
	}
}

// UserAction executes a user action, such as `login`
// This is provided to allow modules to execute global actions as a given user across the API boundaries
// For example, this allows 2fa to be used to validate a user action
// TODO: a more elegant solution to this could be nice.
func (c *AuthPlzCtx) UserAction(userid, action string, rw web.ResponseWriter, req *web.Request) {
	switch action {
	case "login":
		c.LoginUser(userid, rw, req)
	case "recover":
		c.BindRecoveryRequest(userid, rw, req)
	case "sudo":
		// TODO: how to propagate duration through to here?
		c.SetSudo(userid, time.Minute*5, rw, req)
	default:
		log.Printf("AuthPlzCtx.UserAction error: unrecognised user action (%s)", action)
	}
}

const (
	redirectSessionKey = "redirect-session"
	redirectURLKey     = "redirect-url"
)

// DoRedirect writes a redirect to the client
func (c *AuthPlzCtx) DoRedirect(url string, rw web.ResponseWriter, req *web.Request) {
	http.Redirect(rw, req.Request, url, http.StatusFound)
}

// BindRedirect binds a redirect URL to the user session
// This is called post-login (or other action) to allow users to return to
func (c *AuthPlzCtx) BindRedirect(url string, rw web.ResponseWriter, req *web.Request) {
	c.BindInst(rw, req, redirectSessionKey, redirectURLKey, url)
}

// GetRedirect fetches a redirect from a user session to allow for
// post-login (or re-auth) user redirection
func (c *AuthPlzCtx) GetRedirect(rw web.ResponseWriter, req *web.Request) string {
	url, err := c.GetInst(rw, req, redirectSessionKey, redirectURLKey)
	if err != nil {
		return ""
	}

	urlStr, ok := url.(string)
	if !ok {
		return ""
	}

	return urlStr
}
