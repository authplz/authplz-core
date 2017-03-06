/*
 * TOTP Module Controller
 * This defines the TOTP module controller
 *
 * AuthEngine Project (https://github.com/ryankurte/authengine)
 * Copyright 2017 Ryan Kurte
 */

package totp

import (
	"encoding/gob"
	"log"

	"github.com/gocraft/web"
	"github.com/pquerna/otp"
	totp "github.com/pquerna/otp/totp"
)

func init() {
	gob.Register(&otp.Key{})
}

// Controller TOTP controller instance
type Controller struct {
	url       string
	totpStore Storer
}

// NewController creates a new TOTP controller
func NewController(url string, totpStore Storer) *Controller {
	return &Controller{
		url:       url,
		totpStore: totpStore,
	}
}

// Helper middleware to bind module to API context
func bindTOTPContext(totpModule *Controller) func(ctx *totpAPICtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *totpAPICtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.totpModule = totpModule
		next(rw, req)
	}
}

// BindAPI Binds the API for the totp module to the provided router
func (totpModule *Controller) BindAPI(router *web.Router) {
	// Create router for user modules
	totpRouter := router.Subrouter(totpAPICtx{}, "/api/totp")

	// Attach module context
	totpRouter.Middleware(bindTOTPContext(totpModule))
	totpRouter.Middleware(totpSessionMiddleware)

	// Bind endpoints
	totpRouter.Get("/enrol", (*totpAPICtx).TOTPEnrolGet)
	totpRouter.Post("/enrol", (*totpAPICtx).TOTPEnrolPost)
	totpRouter.Get("/authenticate", (*totpAPICtx).TOTPAuthenticateGet)
	totpRouter.Post("/authenticate", (*totpAPICtx).TOTPAuthenticatePost)
	totpRouter.Get("/tokens", (*totpAPICtx).TOTPListTokens)
}

// CreateToken creates a TOTP token for the provided account
func (totpModule *Controller) CreateToken(userid string) (*otp.Key, error) {
	// Generate token
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpModule.url,
		AccountName: userid,
	})
	if err != nil {
		log.Printf("TOTPModule CreateToken: error generating totp token (%s)", err)
		return nil, err
	}
	return key, err
}

// ValidateToken validates a totp token for a given user
func (totpModule *Controller) ValidateToken(userid string, token string) (bool, error) {
	// Fetch tokens
	tokens, err := totpModule.totpStore.GetTotpTokens(userid)
	if err != nil {
		log.Printf("TOTPModule.ValidateToken: error loading tokens for user (%s)", err)
		return false, err
	}

	// Check for matches
	for _, t := range tokens {
		valid := totp.Validate(token, t.(TokenInterface).GetSecret())
		if valid {
			return true, nil
		}
	}

	return false, nil
}

// SaveToken saves a token to a given user
func (totpModule *Controller) SaveToken(userid string, secret string) error {

	return nil
}
