package app

import "github.com/gorilla/sessions"

import "github.com/gocraft/web"

import "github.com/ryankurte/authplz/usercontroller"
import "github.com/ryankurte/authplz/token"
import "github.com/ryankurte/authplz/datastore"
import "github.com/ryankurte/authplz/api"

// Application global context
// TODO: this could be split and bound by module
type AuthPlzGlobalCtx struct {
	port            string
	address         string
	userController  *usercontroller.UserController
	tokenController *token.TokenController
	sessionStore    *sessions.CookieStore
}

// Application handler context
type AuthPlzCtx struct {
	global  *AuthPlzGlobalCtx
	session *sessions.Session
	userid  string
	message string
}

// Convenience type to describe middleware functions
type MiddlewareFunc func(ctx *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc)

// Bind global context object into the router context
func BindContext(globalCtx *AuthPlzGlobalCtx) MiddlewareFunc {
	return func(ctx *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.global = globalCtx
		next(rw, req)
	}
}

// User session layer
func (ctx *AuthPlzCtx) SessionMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	session, err := ctx.global.sessionStore.Get(req.Request, "user-session")
	if err != nil {
		next(rw, req)
		return
	}

	// Save session for further use
	ctx.session = session

	// Load user from session if set
	// TODO: this will be replaced with sessions when implemented
	if session.Values["userId"] != nil {
		//TODO: find user account
		ctx.userid = session.Values["userId"].(string)
	}

	session.Save(req.Request, rw)
	next(rw, req)
}

func (c *AuthPlzCtx) RequireAccountMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	if c.userid == "" {
		c.WriteApiResult(rw, api.ApiResultError, "You must be signed in to view this page")
	} else {
		next(rw, req)
	}
}

func (c *AuthPlzCtx) LoginUser(u *datastore.User, rw web.ResponseWriter, req *web.Request) {
	c.session.Values["userId"] = u.ExtId
	c.session.Save(req.Request, rw)
	c.userid = u.ExtId
}

func (c *AuthPlzCtx) LogoutUser(rw web.ResponseWriter, req *web.Request) {
	c.session.Options.MaxAge = -1
	c.session.Save(req.Request, rw)
	c.userid = ""
}

func (c *AuthPlzCtx) SetFlashMessage(message string, rw web.ResponseWriter, req *web.Request) {
	session, err := c.global.sessionStore.Get(req.Request, "user-message")
	if err != nil {
		return
	}
	session.AddFlash(message)

	c.session.Save(req.Request, rw)
}

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
