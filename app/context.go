package app

import(
"net"
"net/http"
 "log"
 "encoding/json"
)

import (
	"github.com/gocraft/web"
	"github.com/gorilla/sessions"

	"github.com/ryankurte/authplz/api"
	"github.com/ryankurte/authplz/token"
	"github.com/ryankurte/authplz/user"
)

// Application global context
// TODO: this should probably be split and bound by module
type AuthPlzGlobalCtx struct {
	port            string
	address         string
	url             string
	userController  *user.UserModule
	tokenController *token.TokenController
	sessionStore    *sessions.CookieStore
}

// Application handler context
type AuthPlzCtx struct {
	global       *AuthPlzGlobalCtx
	session      *sessions.Session
	userid       string
	message      string
	remoteAddr   string
	forwardedFor string
	locale       string
}

// Convenience type to describe middleware functions
type MiddlewareFunc func(ctx *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc)

// Helper to bind the global context object into the router context
// This is a closure to run over an instance of the global context
func BindContext(globalCtx *AuthPlzGlobalCtx) MiddlewareFunc {
	return func(ctx *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.global = globalCtx
		next(rw, req)
	}
}

// Helper to write objects out as JSON
func (ctx *AuthPlzCtx) WriteJson(w http.ResponseWriter, i interface{}) {
	js, err := json.Marshal(i)
	if err != nil {
		log.Print(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

// Helper to write API results out
func (ctx *AuthPlzCtx) WriteApiResult(w http.ResponseWriter, result string, message string) {
	apiResp := api.ApiResponse{Result: result, Message: message}
	ctx.WriteJson(w, apiResp)
}

// Fetch the APIMessageContainer for a given language to provide locale specific response messages
func (c *AuthPlzCtx) GetApiMessageInst() *api.ApiMessageContainer {
	return api.GetApiLocale(c.locale)
}

// User session layer
// Middleware matches user session if it exists and saves userid to the session object
func (ctx *AuthPlzCtx) SessionMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	session, err := ctx.global.sessionStore.Get(req.Request, "user-session")
	if err != nil {
		log.Printf("Error binding session, %s", err)
		// Poison invalid session so next request will succeed
		session.Options.MaxAge = -1
		session.Save(req.Request, rw)
		return
	}

	// Save session for further use
	ctx.session = session

	// Load user from session if set
	// TODO: this will be replaced with sessions when implemented
	if session.Values["userId"] != nil {

		// Check user account exists
		// TODO: this is inefficient, but, bad shit happens if an account is deleted between API calls
		// Need better session management
		u, err := ctx.global.userController.GetUser(ctx.userid)
		if (err != nil) || (u == nil) {
			log.Printf("Session middleware: user token invalid %s", ctx.userid)
			session.Options.MaxAge = -1
		} else {
			ctx.userid = session.Values["userId"].(string)
		}
	}

	session.Save(req.Request, rw)
	next(rw, req)
}

// Middleware to grab IP & forwarding headers and store in session
func (ctx *AuthPlzCtx) GetIPMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	ctx.remoteAddr, _, _ = net.SplitHostPort(req.RemoteAddr)
	ctx.forwardedFor = req.Header.Get("x-forwarded-for")

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

// Middleware to ensure only logged in access to an endpoint
func (c *AuthPlzCtx) RequireAccountMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	if c.userid == "" {
		c.WriteApiResult(rw, api.ApiResultError, "You must be signed in to view this page")
	} else {
		next(rw, req)
	}
}

type User interface {
	GetExtId() string
	GetEmail() string
}

// Helper function to login a user
func (c *AuthPlzCtx) LoginUser(u User, rw web.ResponseWriter, req *web.Request) {
	if c.session == nil {
		log.Printf("Error logging in user, no session found")
		return
	}
	c.session.Values["userId"] = u.GetExtId()
	c.session.Save(req.Request, rw)
	c.userid = u.GetExtId()
}

// Helper function to logout a user
func (c *AuthPlzCtx) LogoutUser(rw web.ResponseWriter, req *web.Request) {
	c.session.Options.MaxAge = -1
	c.session.Save(req.Request, rw)
	c.userid = ""
}

// Helper function to set a flash message for display to the user
func (c *AuthPlzCtx) SetFlashMessage(message string, rw web.ResponseWriter, req *web.Request) {
	session, err := c.global.sessionStore.Get(req.Request, "user-message")
	if err != nil {
		return
	}
	session.AddFlash(message)

	c.session.Save(req.Request, rw)
}

// Helper function to get a flash message to display to the user
func (c *AuthPlzCtx) GetFlashMessage(rw web.ResponseWriter, req *web.Request) string {
	session, err := c.global.sessionStore.Get(req.Request, "user-message")
	if err != nil {
		return ""
	}

	flashes := session.Flashes()
	if len(flashes) > 0 {
		return flashes[0].(string)
	}

	return ""
}
