/*
 * Core API
 * This defines API for the core module including base login/logout/reset/action endpoints.
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package core

import (
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
	coreRouter.Post("/logout", (*coreCtx).Logout)
	coreRouter.Get("/action", (*coreCtx).Action)
	coreRouter.Post("/action", (*coreCtx).Action)
	coreRouter.Get("/recovery", (*coreCtx).RecoverGet)
	coreRouter.Post("/recovery", (*coreCtx).RecoverPost)
	coreRouter.Get("/2fa-status", (*coreCtx).SecondFactorStatus)
	coreRouter.Get("/test", (*coreCtx).TestGet)
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

	log.Printf("CoreAPI.Action Received action token")

	// If the user isn't logged in
	if c.GetUserID() == "" {
		session := c.GetSession()

		// Clear existing flashes (by reading)
		_ = session.Flashes()

		// Add token to flash and redirect
		session.AddFlash(tokenString)
		session.Save(req.Request, rw)

		log.Printf("CoreAPI.Action saved token to session store")

		c.DoRedirect("/#login", rw, req)

	} else {
		//Handle any active-user tokens here (when implemented)
		c.WriteAPIResultWithCode(rw, http.StatusNotImplemented, api.NotImplemented)
	}
}

// Login to a user account
// This is probably the most interesting endpoint IMO
func (c *coreCtx) Login(rw web.ResponseWriter, req *web.Request) {

	// Fetch parameters
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		log.Printf("Core.Login invalid request (missing email)")
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.InvalidEmail)
		return
	}
	password := req.FormValue("password")
	if password == "" {
		log.Printf("Core.Login invalid request (missing password)")
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
	user, castOk := u.(UserInterface)
	if !loginOk || !castOk {
		log.Println("Core.Login Failure: user account not found")
		c.WriteUnauthorized(rw)
		return
	}

	// Load flashes and apply actions if they exist
	flashes := c.GetSession().Flashes()
	if len(flashes) > 0 {
		log.Printf("Core.Login: found session flash")

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
		log.Printf("Core.Login: PreLogin handler error (%s)\n", err)
		c.WriteInternalError(rw)
		return
	}
	if !preLoginOk {
		log.Printf("Core.Login: PreLogin handler blocked login\n")
		c.WriteAPIResultWithCode(rw, http.StatusUnauthorized, api.AccountLocked)
		return
	}

	// Check for available second factors
	secondFactorRequired, factorsAvailable := c.cm.CheckSecondFactors(user.GetExtID())

	// Respond with list of available 2fa components if required
	if loginOk && preLoginOk && secondFactorRequired {
		log.Println("Core.Login: Partial login (2fa required)")
		c.Bind2FARequest(rw, req, user.GetExtID(), "login")
		c.WriteJSONWithStatus(rw, http.StatusAccepted, factorsAvailable)
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

		c.WriteAPIResult(rw, api.LoginSuccessful)
		return
	}

	// Should be impossible to hit this
	log.Printf("Core.Login: Login failed (unknown)\n")
	c.WriteInternalError(rw)
}

func (c *coreCtx) SecondFactorStatus(rw web.ResponseWriter, req *web.Request) {
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	// Check for available second factors
	_, factorsAvailable := c.cm.CheckSecondFactors(c.GetUserID())

	c.WriteJSON(rw, factorsAvailable)
}

// Logout Endpoint ends a user session
func (c *coreCtx) Logout(rw web.ResponseWriter, req *web.Request) {
	c.LogoutUser(rw, req)

	if c.GetUserID() == "" {
		c.WriteAPIResult(rw, api.LoginRequired)
		return
	}

	c.WriteAPIResult(rw, api.LogoutSuccessful)
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
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.MissingEmail)
		return
	}

	// Save recovery status to session
	c.GetSession().Values[recoveryEmailKey] = email
	c.GetSession().Save(req.Request, rw)

	// Start password reset process (creates event and prompts email sending)
	err := c.cm.PasswordResetStart(email, c.GetMeta())
	if err != nil {
		log.Printf("Core.RecoverPost error starting recovery for user %s (%s)", email, err)
	}

	log.Printf("Core.RecoverPost started recovery for user %s", email)

	c.WriteAPIResult(rw, api.OK)
}

// RecoverGet handles an account recovery token
func (c *coreCtx) RecoverGet(rw web.ResponseWriter, req *web.Request) {
	tokenString := req.URL.Query().Get("token")
	if tokenString == "" {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.MissingToken)
		return
	}

	// Fetch recovery session key
	// This requires recovery tokens to be requested and applied on the same device
	if c.GetSession().Values[recoveryEmailKey] == nil {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.NoRecoveryPending)
		return
	}
	email := c.GetSession().Values[recoveryEmailKey].(string)

	// Validate recovery token
	ok, u, err := c.cm.HandleRecoveryToken(email, tokenString)
	if err != nil {
		c.WriteInternalError(rw)
		return
	}
	if !ok {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.InvalidToken)
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
		c.WriteJSONWithStatus(rw, http.StatusAccepted, factorsAvailable)
		return
	}

	// Bind recovery request flag to session
	c.BindRecoveryRequest(user.GetExtID(), rw, req)

	log.Printf("Core.RecoverGet bound recovery session for user %s", user.GetExtID())

	// Return OK
	c.WriteAPIResult(rw, api.OK)
}

// TestGet test endpoint
func (c *coreCtx) TestGet(rw web.ResponseWriter, req *web.Request) {
	c.WriteAPIResult(rw, api.OK)
}
