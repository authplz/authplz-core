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
	"time"

	"github.com/gocraft/web"
	"github.com/pquerna/otp"
	totp "github.com/pquerna/otp/totp"
)

func init() {
	gob.Register(&otp.Key{})
}

// Controller TOTP controller instance
type Controller struct {
	issuerName string
	totpStore  Storer
}

// NewController creates a new TOTP controller
func NewController(issuerName string, totpStore Storer) *Controller {
	return &Controller{
		issuerName: issuerName,
		totpStore:  totpStore,
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

	// Fetch user account
	u, err := totpModule.totpStore.GetUserByExtId(userid)
	if err != nil {
		log.Printf("TOTPModule CreateToken: error fetching user instance (%s)", err)
	}
	user := u.(User)

	// Generate token
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpModule.issuerName,
		AccountName: user.GetEmail(),
	})
	if err != nil {
		log.Printf("TOTPModule CreateToken: error generating totp token (%s)", err)
		return nil, err
	}
	return key, err
}

// ValidateToValidateRegistrationken validates a totp token registration for a given user
// and enrols the token if valid
func (totpModule *Controller) ValidateRegistration(userid, tokenName, secret, token string) (bool, error) {

	// Check token matches key
	valid := totp.Validate(token, secret)
	if !valid {
		return false, nil
	}

	// Create token instance
	_, err := totpModule.totpStore.AddTotpToken(userid, tokenName, secret, 0)
	if err != nil {
		log.Printf("TOTPModule.ValidateRegistration: error creating token object (%s)", err)
		return false, err
	}

	return true, nil
}

// ValidateToken validates a totp token for a given user
// This is used to check a user provided token against the set of registered totp keys
func (totpModule *Controller) ValidateToken(userid string, token string) (bool, error) {
	// Fetch tokens
	tokens, err := totpModule.totpStore.GetTotpTokens(userid)
	if err != nil {
		log.Printf("TOTPModule.ValidateToken: error loading tokens for user (%s)", err)
		return false, err
	}

	// Check for matches
	var validToken TokenInterface
	validated := false
	for _, t := range tokens {
		valid := totp.Validate(token, t.(TokenInterface).GetSecret())
		if valid {
			validated = true
			validToken = t.(TokenInterface)
		}
	}

	// Return error if validation failed
	if !validated {
		return false, nil
	}

	// Update token last used time and counter
	validToken.SetCounter(validToken.GetCounter() + 1)
	validToken.SetLastUsed(time.Now())

	// Write updates to database
	_, err = totpModule.totpStore.UpdateTotpToken(validToken)
	if err != nil {
		log.Printf("TOTPModule.ValidateToken: error updating token object (%s)", err)
		return false, err
	}

	return true, nil
}
