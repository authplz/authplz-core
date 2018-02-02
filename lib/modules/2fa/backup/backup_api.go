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
	backupCodeRouter.Get("/create", (*backupCodeAPICtx).CreateTokens)
	backupCodeRouter.Post("/authenticate", (*backupCodeAPICtx).AuthenticatePost)
	backupCodeRouter.Get("/codes", (*backupCodeAPICtx).ListTokens)
	backupCodeRouter.Get("/clear", (*backupCodeAPICtx).RemoveTokens)
}

// CreateTokens creates a set of backup codes and returns them to the user
func (c *backupCodeAPICtx) CreateTokens(rw web.ResponseWriter, req *web.Request) {
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
			log.Printf("BackupCodeApiCtx.CreateTokens: error clearing pending backup codes (%s)", err)
			c.WriteInternalError(rw)
			return
		}
	}

	// Create new codes
	codes, err := c.backupCodeModule.CreateCodes(c.GetUserID())
	if err != nil {
		log.Printf("BackupCodeApiCtx.CreateTokens: error creating backup codes (%s)", err)
		c.WriteInternalError(rw)
		return
	}

	// Return response
	c.WriteJSON(rw, codes)
}

// AuthenticatePost authenticates a backup code
func (c *backupCodeAPICtx) AuthenticatePost(rw web.ResponseWriter, req *web.Request) {

	// Fetch challenge user ID
	userid, action := c.Get2FARequest(rw, req)
	if userid == "" {
		log.Printf("BackupCodeAPICtx.AuthenticatePost No pending 2fa requests found")
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorNoRequestSession)
		return
	}

	log.Printf("BackupCodeAPICtx.AuthenticatePost Authentication request for user %s", userid)

	// Fetch challenge code
	code := req.FormValue("code")

	ok, err := c.backupCodeModule.ValidateCode(userid, code)
	if err != nil {
		log.Printf("backupCodeAuthenticatePost: error validating backup code (%s)", err)
		c.WriteInternalError(rw)
		return
	}

	if !ok {
		log.Printf("BackupCodeAPICtx.AuthenticatePost: authentication failed for user %s\n", userid)
		c.WriteAPIResultWithCode(rw, http.StatusUnauthorized, api.SecondFactorFailed)
		return
	}

	c.UserAction(userid, action, rw, req)

	c.WriteAPIResult(rw, api.SecondFactorSuccess)
}

// List backup tokens
func (c *backupCodeAPICtx) ListTokens(rw web.ResponseWriter, req *web.Request) {
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

func (c *backupCodeAPICtx) RemoveTokens(rw web.ResponseWriter, req *web.Request) {
	err := c.backupCodeModule.ClearPendingTokens(c.GetUserID())
	if err != nil {
		log.Printf("BackupCodeAPICtx.RemoveTokens: error clearing pending backup codes (%s)", err)
		c.WriteInternalError(rw)
		return
	}
	c.WriteAPIResult(rw, api.BackupTokensRemoved)
}
