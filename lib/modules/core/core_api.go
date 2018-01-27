package core

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/asaskevich/govalidator"
	"github.com/gocraft/web"

	"github.com/authplz/authplz-core/lib/api"
	"github.com/authplz/authplz-core/lib/appcontext"
)

// Temporary mapping between contexts
type coreCtx struct {
	// Base context for shared components
	*appcontext.AuthPlzCtx

	// Core module to provide API with required methods
	cm *Controller
}

// Helper middleware to bind module to API context
func bindCoreContext(coreModule *Controller) func(ctx *coreCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *coreCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.cm = coreModule
		next(rw, req)
	}
}

// BindAPI Binds the API for the coreModule to the provided router
func (coreModule *Controller) BindAPI(router *web.Router) {
	// Create router for user modules
	coreRouter := router.Subrouter(coreCtx{}, "/api")

	// Attach module context
	coreRouter.Middleware(bindCoreContext(coreModule))

	// Bind endpoints
	coreRouter.Post("/login", (*coreCtx).Login)
	coreRouter.Get("/logout", (*coreCtx).Logout)
	coreRouter.Get("/action", (*coreCtx).Action)
	coreRouter.Post("/action", (*coreCtx).Action)
	coreRouter.Get("/recovery", (*coreCtx).RecoverGet)
	coreRouter.Post("/recovery", (*coreCtx).RecoverPost)
}

// Handle an action token (both get and post calls)
// This adds the action token to a session flash for use post-login attempt
func (c *coreCtx) Action(rw web.ResponseWriter, req *web.Request) {
	// Grab token string from get or post request
	var tokenString string
	tokenString = req.FormValue("token")
	if tokenString == "" {
		tokenString = req.URL.Query().Get("token")
	}
	if tokenString == "" {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.ActionMissing)
		return
	}

	log.Printf("core.Action Received activation token")

	// If the user isn't logged in
	if c.GetUserID() == "" {
		session := c.GetSession()

		// Clear existing flashes (by reading)
		_ = session.Flashes()

		// Add token to flash and redirect
		session.AddFlash(tokenString)
		session.Save(req.Request, rw)

		//TODO: session flash here?

		c.DoRedirect("/#login", rw, req)

	} else {
		//TODO: handle any active-user tokens here
		c.WriteAPIResultWithCode(rw, http.StatusNotImplemented, api.NotImplemented)
	}
}

// Login to a user account
func (c *coreCtx) Login(rw web.ResponseWriter, req *web.Request) {

	// Fetch parameters
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.InvalidEmail)
		return
	}
	password := req.FormValue("password")
	if password == "" {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.MissingPassword)
		return
	}

	// Check user is not already logged in
	if c.GetUserID() != "" {
		log.Printf("Core.Login: user already authenticated (%s)\n", c.GetUserID())
		c.WriteAPIResult(rw, api.AlreadyAuthenticated)
		return
	}

	// Attempt login via UserControl interface
	loginOk, u, e := c.cm.userControl.Login(email, password)
	if e != nil {
		// Run post login failure handlers
		err := c.cm.PostLoginFailure(u)
		if err != nil {
			log.Printf("Core.Login: PostLoginFailure error (%s)\n", err)
			c.WriteInternalError(rw)
			return
		}

		c.WriteInternalError(rw)
		log.Printf("Core.Login: user controller error %s\n", e)
		return
	}

	// Reject invalid credentials
	if !loginOk {
		log.Printf("Core.Login: invalid credentials\n")
		c.WriteUnauthorized(rw)
		return
	}

	// No user account found
	// TODO: this cannot fail anymore
	user, castOk := u.(UserInterface)
	if !loginOk || !castOk {
		log.Println("Core.Login Failure: user account not found")
		c.WriteUnauthorized(rw)
		return
	}

	// Load flashes and apply actions if they exist
	flashes := c.GetSession().Flashes()
	if len(flashes) > 0 {
		// Fetch token from session flash
		tokenString := flashes[0].(string)

		// Handle token and call require action
		tokenOk, err := c.cm.HandleToken(user.GetExtID(), user, tokenString)
		if err != nil {
			c.WriteInternalError(rw)
			return
		}
		if !tokenOk {
			c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.InvalidToken)
			return
		}

		// Reload login state
		loginOk, u, e = c.cm.userControl.Login(email, password)
		if e != nil {
			c.WriteInternalError(rw)
			log.Printf("Core.Login: user controller error %s\n", e)
			return
		}
		user = u.(UserInterface)
	}

	// Call PreLogin handlers
	preLoginOk, err := c.cm.PreLogin(u)
	if err != nil {
		log.Printf("Core.Login: PreLogin error (%s)\n", err)
		c.WriteInternalError(rw)
		return
	}
	if !preLoginOk {
		log.Printf("Core.Login: PreLogin blocked login\n")
		c.WriteAPIResultWithCode(rw, http.StatusUnauthorized, api.AccountLocked)
		return
	}

	// Check for available second factors
	secondFactorRequired, factorsAvailable := c.cm.CheckSecondFactors(user.GetExtID())

	// Respond with list of available 2fa components if required
	if loginOk && preLoginOk && secondFactorRequired {
		log.Println("Core.Login: Partial login (2fa required)")
		c.Bind2FARequest(rw, req, user.GetExtID(), "login")

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusAccepted)
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
		err := c.cm.PostLoginSuccess(u)
		if err != nil {
			log.Printf("Core.Login: PostLoginSuccess error (%s)\n", err)
			c.WriteInternalError(rw)
			return
		}

		log.Printf("Core.Login: Login OK for user: %s", user.GetExtID())

		// Create session
		c.LoginUser(user.GetExtID(), rw, req)

		rw.WriteHeader(http.StatusOK)
		c.WriteAPIResult(rw, api.LoginSuccessful)
		return
	}

	// Should be impossible to hit this
	log.Printf("Core.Login: Login failed (unknown)\n")
	c.WriteInternalError(rw)
}

// Logout Endpoint ends a user session
func (c *coreCtx) Logout(rw web.ResponseWriter, req *web.Request) {
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	c.LogoutUser(rw, req)

	rw.WriteHeader(http.StatusOK)
}

// Recover endpoints provide mechanisms for user account recovery

const (
	recoverySessionKey = "recovery-session"
	recoveryEmailKey   = "recovery-email"
)

// RecoverPost takes an email input to start the recovery process
func (c *coreCtx) RecoverPost(rw web.ResponseWriter, req *web.Request) {
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Save recovery status to session
	c.GetSession().Values[recoveryEmailKey] = email
	c.GetSession().Save(req.Request, rw)

	// TODO: Generate and send recovery email
	err := c.cm.PasswordResetStart(email)
	if err != nil {
		log.Printf("Core.RecoverPost error starting recovery for user %s (%s)", email, err)
	}

	log.Printf("Core.RecoverPost started recovery for user %s", email)

	rw.WriteHeader(http.StatusOK)
}

// RecoverGet handles an account recovery token
func (c *coreCtx) RecoverGet(rw web.ResponseWriter, req *web.Request) {
	tokenString := req.URL.Query().Get("token")
	if tokenString == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Fetch recovery session key
	// This requires recovery tokens to be requested and applied on the same device
	if c.GetSession().Values[recoveryEmailKey] == nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	email := c.GetSession().Values[recoveryEmailKey].(string)

	// Validate recovery token
	ok, u, err := c.cm.HandleRecoveryToken(email, tokenString)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !ok {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	user := u.(UserInterface)

	log.Printf("Core.RecoverGet continuing recovery for user %s", user.GetExtID())

	// Check if 2fa is required
	secondFactorRequired, factorsAvailable := c.cm.CheckSecondFactors(user.GetExtID())
	if secondFactorRequired {
		log.Printf("Core.RecoverGet recovery requires 2fa for user %s", user.GetExtID())

		// Bind 2fa request with recovery action
		// c.UserAction will be called at completion with the recover action
		c.Bind2FARequest(rw, req, user.GetExtID(), "recover")

		// Write available factors to client
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

	// Bind recovery request flag to session
	c.BindRecoveryRequest(user.GetExtID(), rw, req)

	log.Printf("Core.RecoverGet bound recovery session for user %s", user.GetExtID())

	// Return OK
	rw.WriteHeader(http.StatusOK)
}
