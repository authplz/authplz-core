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

		rw.WriteHeader(http.StatusOK)
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
		rw.WriteHeader(http.StatusOK)
	}

	// Attempt login via UserControl interface
	loginOk, u, e := c.cm.userControl.Login(email, password)
	if e != nil {
		// Run post login failure handlers
		err := c.cm.PostLoginFailure(u);
		if err != nil {
			log.Printf("Core.Login: PostLoginFailure error (%s)\n", err)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}

		rw.WriteHeader(http.StatusUnauthorized)
		log.Printf("Core.Login: user controller error %s\n", e)
		return
	}

	// Reject invalid credentials
	if !loginOk {
		log.Printf("Core.Login: invalid credentials\n")
		rw.WriteHeader(http.StatusUnauthorized)
	}

	// No user account found
	// TODO: this cannot fail anymore
	user, castOk := u.(UserInterface)
	if !loginOk || !castOk {
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
		tokenOk, err := c.cm.HandleToken(user.GetExtId(), user, tokenString)
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !tokenOk {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		// Reload login state
		loginOk, u, e = c.cm.userControl.Login(email, password)
		if e != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			log.Printf("Core.Login: user controller error %s\n", e)
			return
		}
		user = u.(UserInterface)
	}

	// Call PreLogin handlers
	preLoginOk, err := c.cm.PreLogin(u)
	if err != nil {
		log.Printf("Core.Login: PreLogin error (%s)\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !preLoginOk {
		log.Printf("Core.Login: PreLogin blocked login\n")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Check for available second factors
	secondFactorRequired, factorsAvailable := c.cm.CheckSecondFactors(c.GetUserID())

	// Respond with list of available 2fa components if required
	if loginOk && preLoginOk && secondFactorRequired {
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
	if loginOk && preLoginOk {
		// Run post login success handlers
		err := c.cm.PostLoginSuccess(u);
		if err != nil {
			log.Printf("Core.Login: PostLoginSuccess error (%s)\n", err)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Println("Core.Login: Login OK")

		// Create session
		c.LoginUser(user.GetExtId(), rw, req)
		rw.WriteHeader(http.StatusOK)
		return
	}

	// Should be impossible to hit this
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
		rw.WriteHeader(http.StatusOK)
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
