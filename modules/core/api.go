package core

import (
	"log"
	"net/http"
	"encoding/json"
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

	// TODO: handle UserControl.Login errors

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
		// Fetch token from session flash and validate
		tokenString := flashes[0].(string)
		action, err := c.cm.tokenControl.ValidateToken(user.GetExtId(), tokenString)
		if err != nil {
			log.Printf("Core.Login: Token error %s\n", err)
			//c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InvalidToken)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Locate token handler
		tokenHandler, ok := c.cm.tokenHandlers[*action]
		if !ok {
			log.Printf("Core.Login: No token handler found for action %s\n", action)
		}

		// Execute token action
		err = tokenHandler.HandleToken(user, *action)
		if err != nil {
			log.Printf("Core.Login: Token action %s handler error %s\n", action, err)
		}

		// Reload login state
		l, _, e = c.cm.userControl.Login(email, password)
		if e != nil {
			rw.WriteHeader(http.StatusUnauthorized)
			log.Printf("Core.Login: user controller error %s\n", e)
			return
		}
	}

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

	// Check for available second factors
	availableHandlers := make(map[string]bool)
	secondFactorRequired := false
	for key, handler := range c.cm.secondFactorHandlers {
		supported := handler.IsSupported(user.GetExtId())
		if supported {
			secondFactorRequired = true
		}
		availableHandlers[key] = supported
	}
	log.Printf("Second factors: %+v", availableHandlers)

	// Respond with list of available 2fa components if required
	if (l == api.LoginSuccess) && secondFactorRequired {
		log.Println("Core.Login: Partial login (2fa required)")
		c.Bind2FARequest(rw, req, user.GetExtId())

		rw.WriteHeader(http.StatusAccepted)
		rw.Header().Set("Content-Type", "application/json")
		js, err := json.Marshal(availableHandlers)
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
