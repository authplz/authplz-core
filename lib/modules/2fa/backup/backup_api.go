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
	backupCodeRouter.Get("/create", (*backupCodeAPICtx).BackupCodesCreate)
	backupCodeRouter.Post("/authenticate", (*backupCodeAPICtx).BackupCodeAuthenticatePost)
	backupCodeRouter.Get("/codes", (*backupCodeAPICtx).BackupCodeListTokens)
	backupCodeRouter.Get("/clear", (*backupCodeAPICtx).BackupCodeRemoveTokens)
}

// BackupCodesCreate creates a set of backup codes and returns them to the user
func (c *backupCodeAPICtx) BackupCodesCreate(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	overwrite := req.FormValue("overwrite")

	// Check if codes already exist, then decide what to do
	supported := c.backupCodeModule.IsSupported(c.GetUserID())
	if supported && overwrite == "" {
		// No overwrite flag, return an API error
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.BackupTokenOverwriteRequired)
		return
	} else if supported && overwrite == "true" {
		// Overwrite flag, clear pending tokens and continue
		err := c.backupCodeModule.ClearPendingTokens(c.GetUserID())
		if err != nil {
			log.Printf("backupCodeAuthenticatePost: error clearing pending backup codes (%s)", err)
			c.WriteInternalError(rw)
			return
		}
	}

	// Create new codes
	codes, err := c.backupCodeModule.CreateCodes(c.GetUserID())
	if err != nil {
		log.Printf("backupCodeAuthenticatePost: error creating backup codes (%s)", err)
		c.WriteInternalError(rw)
		return
	}

	// Return response
	c.WriteJSON(rw, codes)
}

// BackupCodeAuthenticatePost authenticates a backup code
func (c *backupCodeAPICtx) BackupCodeAuthenticatePost(rw web.ResponseWriter, req *web.Request) {

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
		log.Printf("backupCodeAuthenticatePost: error validating backup code (%s)", err)
		c.WriteInternalError(rw)
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

// List backup tokens
func (c *backupCodeAPICtx) BackupCodeListTokens(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	// Fetch codes
	codes, err := c.backupCodeModule.ListCodes(c.GetUserID())
	if err != nil {
		log.Printf("Error fetching backupCode tokens %s", err)
		c.WriteInternalError(rw)
		return
	}

	// Write codes out
	c.WriteJSON(rw, codes)
}

func (c *backupCodeAPICtx) BackupCodeRemoveTokens(rw web.ResponseWriter, req *web.Request) {
	err := c.backupCodeModule.ClearPendingTokens(c.GetUserID())
	if err != nil {
		log.Printf("backupCodeAuthenticatePost: error clearing pending backup codes (%s)", err)
		c.WriteInternalError(rw)
		return
	}
	c.WriteAPIResult(rw, api.BackupTokensRemoved)
}
