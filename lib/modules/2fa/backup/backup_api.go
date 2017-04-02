/*
 * (2fa) Backup Code Module API
 * This defines the API methods bound to the Backup Code module
 *
 * AuthPlz Project (https://github.com/ryankurte/AuthPlz)
 * Copyright 2017 Ryan Kurte
 */

package backup

import (
	"log"
	"net/http"

	"github.com/gocraft/web"
	"github.com/gorilla/sessions"
	"github.com/ryankurte/authplz/lib/api"
	"github.com/ryankurte/authplz/lib/appcontext"
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
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// TODO: check if codes already exist, then decide what to do

	// Create new codes
	codes, err := c.backupCodeModule.CreateCodes(c.GetUserID())
	if err != nil {
		log.Printf("backupCodeAuthenticatePost: error validating backupCode code (%s)", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Return response
	c.WriteJson(rw, codes)
}

//backupCodeAuthenticatePost
func (c *backupCodeAPICtx) backupCodeAuthenticatePost(rw web.ResponseWriter, req *web.Request) {

	// Fetch challenge user ID
	userid, action := c.Get2FARequest(rw, req)
	if userid == "" {
		log.Printf("backupCode.backupCodeAuthenticatePost No pending 2fa requests found")
		c.WriteApiResult(rw, api.ResultError, c.GetApiLocale().InternalError)
		return
	}

	log.Printf("backupCode.backupCodeAuthenticatePost Authentication request for user %s", userid)

	// Fetch challenge code
	code := req.FormValue("code")

	ok, err := c.backupCodeModule.ValidateCode(userid, code)
	if err != nil {
		log.Printf("backupCodeAuthenticatePost: error validating backupCode code (%s)", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if !ok {
		log.Printf("backupCodeAuthenticatePost: authentication failed for user %s\n", userid)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	log.Printf("backupCodeAuthenticatePost: Valid authentication for account %s (action %s)\n", userid, action)
	c.UserAction(userid, action, rw, req)
	rw.WriteHeader(http.StatusOK)
}

func (c *backupCodeAPICtx) backupCodeListTokens(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Fetch codes
	codes, err := c.backupCodeModule.ListCodes(c.GetUserID())
	if err != nil {
		log.Printf("Error fetching backupCode tokens %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Write codes out
	c.WriteJson(rw, codes)
}

func (c *backupCodeAPICtx) backupCodeRemoveToken(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}
