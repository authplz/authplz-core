package core

import (
	"encoding/json"
	"log"
	"net/http"
)

import (
	"github.com/asaskevich/govalidator"
	"github.com/gocraft/web"
	"github.com/ryankurte/authplz/api"
	"github.com/ryankurte/authplz/appcontext"
)

// Temporary mapping between contexts
type AuthPlzCoreCtx struct {
	// Base context for shared components
	*appcontext.AuthPlzCtx

	// Core module to provide API with required methods
	cm *CoreModule
}

// Helper middleware to bind module to API context
func BindCoreContext(coreModule *CoreModule) func(ctx *AuthPlzCoreCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *AuthPlzCoreCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.cm = coreModule
		next(rw, req)
	}
}

// Bind the API for the coreModule to the provided router
func (coreModule *CoreModule) BindAPI(router *web.Router) {
	// Create router for user modules
	coreRouter := router.Subrouter(AuthPlzCoreCtx{}, "/api")

	// Attach module context
	coreRouter.Middleware(BindCoreContext(coreModule))

	// Bind endpoints
	coreRouter.Post("/login", (*AuthPlzCoreCtx).Login)
	coreRouter.Get("/logout", (*AuthPlzCoreCtx).Logout)
	coreRouter.Get("/test", (*AuthPlzCoreCtx).Test)
	coreRouter.Get("/action", (*AuthPlzCoreCtx).Action)
	coreRouter.Post("/action", (*AuthPlzCoreCtx).Action)
}

// Test endpoint
func (c *AuthPlzCoreCtx) Test(rw web.ResponseWriter, req *web.Request) {
	c.WriteApiResult(rw, api.ApiResultOk, "Test Response")
}

// Handle an action token (both get and post calls)
// This adds the action token to a session flash for use post-login attempt
func (c *AuthPlzCoreCtx) Action(rw web.ResponseWriter, req *web.Request) {
	// Grab token string from get or post request
	var tokenString string
	tokenString = req.FormValue("token")
	if tokenString == "" {
		tokenString = req.URL.Query().Get("token")
	}
	if tokenString == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// If the user isn't logged in
	if c.GetUserID() == "" {
		session := c.GetSession()

		// Clear existing flashes (by reading)
		_ = session.Flashes()

		// Add token to flash and redirect
		session.AddFlash(tokenString)
		session.Save(req.Request, rw)

		c.WriteApiResult(rw, api.ApiResultOk, "Saved token")
		//TODO: redirect to login

	} else {
		//TODO: handle any active-user tokens here
		rw.WriteHeader(http.StatusNotImplemented)
	}
}

// Login to a user account
func (c *AuthPlzCoreCtx) Login(rw web.ResponseWriter, req *web.Request) {
	// Fetch parameters
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	password := req.FormValue("password")
	if password == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Check user is not already logged in
	if c.GetUserID() != "" {
		c.WriteApiResult(rw, api.ApiResultOk, c.GetApiLocale().AlreadyAuthenticated)
	}

	// Attempt login via UserControl interface
	l, u, e := c.cm.userControl.Login(email, password)
	if e != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		log.Printf("Core.Login: user controller error %s\n", e)
		return
	}

	// No user account found
	user, ok := u.(UserInterface)
	if l == api.LoginFailure || !ok {
		log.Println("Core.Login Failure: user account not found")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Load flashes and apply actions if they exist
	flashes := c.GetSession().Flashes()
	if len(flashes) > 0 {
		// Fetch token from session flash
		tokenString := flashes[0].(string)

		// Handle token and call require action
		ok, err := c.cm.HandleToken(user.GetExtId(), user, tokenString)
		if err != nil {
			c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
			return
		}
		if !ok {
			//c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InvalidToken)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Reload login state
		l, _, e = c.cm.userControl.Login(email, password)
		if e != nil {
			rw.WriteHeader(http.StatusUnauthorized)
			log.Printf("Core.Login: user controller error %s\n", e)
			return
		}
	}

	// TODO: both the following checks could be implemented as plugins to simplify the login controller
	// Handle not yet activated accounts
	if l == api.LoginUnactivated {
		log.Println("Core.Login: Account not activated")
		//TODO: prompt for activation (resend email?)
		rw.WriteHeader(http.StatusUnauthorized)
		//c.WriteApiResult(rw, api.ApiResultError, user.LoginUnactivated.Message);
		return
	}

	// TODO: handle locked accounts
	if l == api.LoginLocked {
		log.Println("Core.Login: Account locked")
		//TODO: prompt for unlock (resend email?)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Call PreLogin handlers
	loginAllowed, err := c.cm.PreLogin(c.GetUserID(), u)
	if err != nil {
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return
	}
	if !loginAllowed {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Check for available second factors
	secondFactorRequired, factorsAvailable := c.cm.CheckSecondFactors(c.GetUserID())

	// Respond with list of available 2fa components if required
	if (l == api.LoginSuccess) && secondFactorRequired {
		log.Println("Core.Login: Partial login (2fa required)")
		c.Bind2FARequest(rw, req, user.GetExtId())

		rw.WriteHeader(http.StatusAccepted)
		rw.Header().Set("Content-Type", "application/json")
		js, err := json.Marshal(factorsAvailable)
		if err != nil {
			log.Print(err)
			return
		}
		rw.Write(js)

		return
	}

	// Handle login success
	if l == api.LoginSuccess {
		log.Println("Core.Login: Login OK")

		// Create session
		c.LoginUser(user.GetExtId(), rw, req)
		c.WriteApiResult(rw, api.ApiResultOk, c.GetApiLocale().LoginSuccessful)
		return
	}

	log.Printf("Core.Login: Login failed (unknown)\n")
	rw.WriteHeader(http.StatusUnauthorized)
}

// End a user session
func (c *AuthPlzCoreCtx) Logout(rw web.ResponseWriter, req *web.Request) {
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	} else {
		c.LogoutUser(rw, req)
		c.WriteApiResult(rw, api.ApiResultOk, c.GetApiLocale().LogoutSuccessful)
	}
}

// Recover a user account
func (c *AuthPlzCoreCtx) Recover(rw web.ResponseWriter, req *web.Request) {
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Send recovery email

	// Check if 2fa tokens are available

}
