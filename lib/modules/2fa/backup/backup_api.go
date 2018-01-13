/*
 * (2fa) Backup Code Module API
 * This defines the API methods bound to the 2fa Backup Code module
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package backup

import (
	"log"
	"net/http"

	"github.com/authplz/authplz-core/lib/api"
	"github.com/authplz/authplz-core/lib/appcontext"
	"github.com/gocraft/web"
	"github.com/gorilla/sessions"
)

// U2F API context storage
type backupCodeAPICtx struct {
	// Base context for shared components
	*appcontext.AuthPlzCtx

	// backupCode controller module
	backupCodeModule *Controller

	// backupCode session
	backupCodeSession *sessions.Session
}

// Helper middleware to bind module to API context
func bindBackupCodeContext(backupCodeModule *Controller) func(ctx *backupCodeAPICtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *backupCodeAPICtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.backupCodeModule = backupCodeModule
		next(rw, req)
	}
}

// BindAPI Binds the API for the totp module to the provided router
func (backupCodeModule *Controller) BindAPI(router *web.Router) {
	// Create router for user modules
	backupCodeRouter := router.Subrouter(backupCodeAPICtx{}, "/api/backupcode")

	// Attach module context
	backupCodeRouter.Middleware(bindBackupCodeContext(backupCodeModule))

	// Bind endpoints
	backupCodeRouter.Get("/create", (*backupCodeAPICtx).backupCodesCreate)
	backupCodeRouter.Post("/authenticate", (*backupCodeAPICtx).backupCodeAuthenticatePost)
	backupCodeRouter.Get("/codes", (*backupCodeAPICtx).backupCodeListTokens)
}

// backupCodeEnrolGet creates a set of backup codes and returns them to the user
func (c *backupCodeAPICtx) backupCodesCreate(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteAPIResultWithCode(rw, http.StatusUnauthorized, api.Unauthorized)
		return
	}

	// TODO: check if codes already exist, then decide what to do

	// Create new codes
	codes, err := c.backupCodeModule.CreateCodes(c.GetUserID())
	if err != nil {
		log.Printf("backupCodeAuthenticatePost: error validating backupCode code (%s)", err)
		c.WriteAPIResultWithCode(rw, http.StatusInternalServerError, api.InternalError)
		return
	}

	// Return response
	c.WriteJSON(rw, codes)
}

//backupCodeAuthenticatePost
func (c *backupCodeAPICtx) backupCodeAuthenticatePost(rw web.ResponseWriter, req *web.Request) {

	// Fetch challenge user ID
	userid, action := c.Get2FARequest(rw, req)
	if userid == "" {
		log.Printf("backupCode.backupCodeAuthenticatePost No pending 2fa requests found")
		c.WriteAPIResult(rw, api.SecondFactorNoRequestSession)
		return
	}

	log.Printf("backupCode.backupCodeAuthenticatePost Authentication request for user %s", userid)

	// Fetch challenge code
	code := req.FormValue("code")

	ok, err := c.backupCodeModule.ValidateCode(userid, code)
	if err != nil {
		log.Printf("backupCodeAuthenticatePost: error validating backupCode code (%s)", err)
		c.WriteAPIResultWithCode(rw, http.StatusInternalServerError, api.InternalError)
		return
	}

	if !ok {
		log.Printf("backupCodeAuthenticatePost: authentication failed for user %s\n", userid)
		c.WriteAPIResultWithCode(rw, http.StatusUnauthorized, api.SecondFactorFailed)
		return
	}

	log.Printf("backupCodeAuthenticatePost: Valid authentication for account %s (action %s)\n", userid, action)
	c.UserAction(userid, action, rw, req)

	c.WriteAPIResult(rw, api.SecondFactorSuccess)
}

func (c *backupCodeAPICtx) backupCodeListTokens(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteAPIResultWithCode(rw, http.StatusUnauthorized, api.Unauthorized)
		return
	}

	// Fetch codes
	codes, err := c.backupCodeModule.ListCodes(c.GetUserID())
	if err != nil {
		log.Printf("Error fetching backupCode tokens %s", err)
		c.WriteAPIResultWithCode(rw, http.StatusInternalServerError, api.InternalError)
		return
	}

	// Write codes out
	c.WriteJSON(rw, codes)
}

func (c *backupCodeAPICtx) backupCodeRemoveToken(rw web.ResponseWriter, req *web.Request) {
	c.WriteAPIResultWithCode(rw, http.StatusNotImplemented, api.NotImplemented)
}
