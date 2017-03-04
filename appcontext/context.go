package appcontext

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
)

import (
	"github.com/gocraft/web"
	"github.com/gorilla/sessions"
	"github.com/ryankurte/authplz/api"
)

// Application global context
// TODO: this should probably be split and bound by module
type AuthPlzGlobalCtx struct {
	port         string
	address      string
	url          string
	SessionStore *sessions.CookieStore
}

func NewGlobalCtx(port, address, url string, sessionStore *sessions.CookieStore) AuthPlzGlobalCtx {
	return AuthPlzGlobalCtx{port, address, url, sessionStore}
}

// Application handler context
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
	GetExtId() string
}

func (ctx *AuthPlzCtx) GetLocale() string {
	return ctx.locale
}

func (ctx *AuthPlzCtx) GetSession() *sessions.Session {
	return ctx.session
}

// Wrapper for API localisation
func (ctx *AuthPlzCtx) GetApiLocale() *api.ApiMessageContainer {
	return api.GetApiLocale(ctx.locale)
}

// Convenience type to describe middleware functions
type MiddlewareFunc func(ctx *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc)

// Helper to bind the global context object into the router context
// This is a closure to run over an instance of the global context
func BindContext(globalCtx *AuthPlzGlobalCtx) MiddlewareFunc {
	return func(ctx *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.Global = globalCtx
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

// User session layer
// Middleware matches user session if it exists and saves userid to the session object
func (ctx *AuthPlzCtx) SessionMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	session, err := ctx.Global.SessionStore.Get(req.Request, "user-session")
	if err != nil {
		log.Printf("Error binding session, %s", err)
		// Poison invalid session so next request will succeed
		session.Options.MaxAge = -1
		session.Save(req.Request, rw)
		return
	}

	// Save session for further use
	ctx.session = session

	// TODO: load user from session

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

// Fetch the APIMessageContainer for a given language to provide locale specific response messages
func (c *AuthPlzCtx) GetApiMessageInst() *api.ApiMessageContainer {
	return api.GetApiLocale(c.locale)
}

// Middleware to ensure only logged in access to an endpoint
func (c *AuthPlzCtx) RequireAccountMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	if c.userid == "" {
		c.WriteApiResult(rw, api.ApiResultError, "You must be signed in to view this page")
	} else {
		next(rw, req)
	}
}

// Helper function to login a user
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

// Helper function to logout a user
func (c *AuthPlzCtx) LogoutUser(rw web.ResponseWriter, req *web.Request) {
	log.Printf("Context: logging out user %d", c.userid)
	c.session.Options.MaxAge = -1
	c.session.Save(req.Request, rw)
	c.userid = ""
}

// Fetch user id from a session
// Blank if a user is not logged in
func (ctx *AuthPlzCtx) GetUserID() string {
	id := ctx.session.Values["userId"]
	if id != nil {
		return id.(string)
	} else {
		return ""
	}
}

// Helper function to set a flash message for display to the user
func (c *AuthPlzCtx) SetFlashMessage(message string, rw web.ResponseWriter, req *web.Request) {
	session, err := c.Global.SessionStore.Get(req.Request, "user-message")
	if err != nil {
		return
	}
	session.AddFlash(message)

	c.session.Save(req.Request, rw)
}

// Helper function to get a flash message to display to the user
func (c *AuthPlzCtx) GetFlashMessage(rw web.ResponseWriter, req *web.Request) string {
	session, err := c.Global.SessionStore.Get(req.Request, "user-message")
	if err != nil {
		return ""
	}

	flashes := session.Flashes()
	if len(flashes) > 0 {
		return flashes[0].(string)
	}

	return ""
}

const secondFactorRequestSessionKey = "2fa-request"

// Bind a 2fa request for a user
// TODO: the request should probably timeout eventually
func (c *AuthPlzCtx) Bind2FARequest(rw web.ResponseWriter, req *web.Request, userid string) {
	secondFactorSession, err := c.Global.SessionStore.Get(req.Request, secondFactorRequestSessionKey)
	if err != nil {
		log.Printf("AuthPlzCtx.Bind2faRequest error fetching %s %s", secondFactorRequestSessionKey, err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return
	}

	log.Printf("AuthPlzCtx.Bind2faRequest adding authorization flash for user %s\n", userid)

	secondFactorSession.Values[secondFactorRequestSessionKey] = userid
	secondFactorSession.Save(req.Request, rw)
}

// Fetch a 2fa request for a user
func (c *AuthPlzCtx) Get2FARequest(rw web.ResponseWriter, req *web.Request) string {
	u2fSession, err := c.Global.SessionStore.Get(req.Request, secondFactorRequestSessionKey)
	if err != nil {
		log.Printf("AuthPlzCtx.Get2FARequest Error fetching %s %s", secondFactorRequestSessionKey, err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return ""
	}

	if u2fSession.Values[secondFactorRequestSessionKey] == nil {
		c.WriteApiResult(rw, api.ApiResultError, "No userid found")
		log.Printf("AuthPlzCtx.Get2FARequest No userid found in session flash")
		return ""
	}
	userid := u2fSession.Values[secondFactorRequestSessionKey].(string)
	return userid
}
