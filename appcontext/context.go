package appcontext

import (
	"log"
	"net"
	"net/http"

	"github.com/gocraft/web"
	"github.com/gorilla/sessions"
	"github.com/ryankurte/authplz/api"
)

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

type User interface {
	GetExtID() string
	IsAdmin() string
}

func (c *AuthPlzCtx) GetSession() *sessions.Session {
	return c.session
}

func (c *AuthPlzCtx) GetLocale() string {
	if c.locale != "" {
		return c.locale
	} else {
		return api.DefaultLocale
	}
}

// Wrapper for API localisation
func (c *AuthPlzCtx) GetApiLocale() *api.ApiMessageContainer {
	return api.GetApiLocale(c.locale)
}

// Convenience type to describe middleware functions
type MiddlewareFunc func(c *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc)

// Helper to bind the global context object into the router context
// This is a closure to run over an instance of the global context
func BindContext(globalCtx *AuthPlzGlobalCtx) MiddlewareFunc {
	return func(ctx *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.Global = globalCtx
		next(rw, req)
	}
}

// User session layer
// Middleware matches user session if it exists and saves userid to the session object
func (c *AuthPlzCtx) SessionMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	session, err := c.Global.SessionStore.Get(req.Request, "user-session")
	if err != nil {
		log.Printf("Error binding session, %s", err)
		// Poison invalid session so next request will succeed
		session.Options.MaxAge = -1
		session.Save(req.Request, rw)
		return
	}

	// Save session for further use
	c.session = session

	// TODO: load user from session

	session.Save(req.Request, rw)
	next(rw, req)
}

// Middleware to grab IP & forwarding headers and store in session
func (c *AuthPlzCtx) GetIPMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	c.remoteAddr, _, _ = net.SplitHostPort(req.RemoteAddr)
	c.forwardedFor = req.Header.Get("x-forwarded-for")

	next(rw, req)
}

// Middleware to grab locale query string or cookies for use in API responses
func (c *AuthPlzCtx) GetLocaleMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	queryLocale := req.URL.Query().Get("locale")
	if queryLocale != "" {
		// Update session locale
		c.locale = queryLocale
		c.session.Values["locale"] = queryLocale
		c.session.Save(req.Request, rw)
	} else {
		// Fetch and save locale to context
		sessionLocale := c.session.Values["locale"]
		if sessionLocale != nil {
			c.locale = sessionLocale.(string)
		} else {
			c.locale = api.DefaultLocale
		}
	}

	next(rw, req)
}

// Fetch the APIMessageContainer for a given language to provide locale specific response messages
func (c *AuthPlzCtx) GetApiMessageInst() *api.ApiMessageContainer {
	return api.GetApiLocale(c.locale)
}

// Middleware to ensure only logged in access to an endpoint
func (c *AuthPlzCtx) RequireAccountMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	if c.userid == "" {
		c.WriteApiResult(rw, api.ResultError, "You must be signed in to view this page")
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
	log.Printf("Context: logged in user %d", userid)
}

// LogoutUser Helper function to logout a user
func (c *AuthPlzCtx) LogoutUser(rw web.ResponseWriter, req *web.Request) {
	log.Printf("Context: logging out user %d", c.userid)
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
// TODO: a more elegant solution to this could be nice.
func (c *AuthPlzCtx) UserAction(userid, action string, rw web.ResponseWriter, req *web.Request) {
	switch action {
	case "login":
		c.LoginUser(userid, rw, req)
	case "recover":
		c.BindRecoveryRequest(userid, rw, req)
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
	http.Redirect(rw, req.Request, url, 302)
}

// BindRedirect binds a redirect URL to the user session
// This is called post-login (or other action) to allow users to return to
func (c *AuthPlzCtx) BindRedirect(url string, rw web.ResponseWriter, req *web.Request) {
	c.BindInst(rw, req, redirectSessionKey, redirectURLKey, url)
}

// GetRedirect fetches a redirect from a user session to allow for
// post-login (or reauth) user redirection
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
