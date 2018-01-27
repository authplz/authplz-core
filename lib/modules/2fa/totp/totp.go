/*
 * TOTP Module Controller
 * This defines the TOTP module controller
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package totp

import (
	"log"
	"time"

	"github.com/authplz/authplz-core/lib/events"

	"github.com/gocraft/web"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Controller TOTP controller instance
type Controller struct {
	issuerName string
	totpStore  Storer
	emitter    events.Emitter
}

// NewController creates a new TOTP controller
// TOTP tokens are issued against the provided issuer name and user email account.
// A CompletedHandler is required for completion of authorization actions, as welll as a Storer to
// provide underlying storage to the TOTP module
func NewController(issuerName string, totpStore Storer, emitter events.Emitter) *Controller {
	return &Controller{
		issuerName: issuerName,
		totpStore:  totpStore,
		emitter:    emitter,
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
	totpRouter.Post("/authenticate", (*totpAPICtx).TOTPAuthenticatePost)
	totpRouter.Get("/tokens", (*totpAPICtx).TOTPListTokens)
}

// IsSupported Checks whether totp is supported for a given user by userid
// This is required to implement the generic 2fa interface for binding into the core module.
func (totpModule *Controller) IsSupported(userid string) bool {
	tokens, err := totpModule.totpStore.GetTotpTokens(userid)
	if err != nil {
		log.Printf("TOTPModule.IsSupported error fetching totp tokens for user %s (%s)", userid, tokens)
		return false
	}
	if len(tokens) == 0 {
		return false
	}
	return true
}

// CreateToken creates a TOTP token for the provided account
func (totpModule *Controller) CreateToken(userid string) (*otp.Key, error) {

	// Fetch user account
	u, err := totpModule.totpStore.GetUserByExtID(userid)
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

// ValidateRegistration validates a totp token registration for a given user and enrols the token if valid
func (totpModule *Controller) ValidateRegistration(userid, tokenName, secret, token string) (bool, error) {

	// Check token matches key
	valid := totp.Validate(token, secret)
	if !valid {
		return false, nil
	}

	// Create token instance
	t, err := totpModule.totpStore.AddTotpToken(userid, tokenName, secret, 0)
	if err != nil {
		log.Printf("TOTPModule.ValidateRegistration: error creating token object (%s)", err)
		return false, err
	}

	log.Printf("TOTPModule.ValidateRegistration: registered token for user %s", userid)

	data := make(map[string]string)
	data["Token Name"] = t.(TokenInterface).GetName()
	totpModule.emitter.SendEvent(events.NewEvent(userid, events.SecondFactorTotpAdded, data))

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

// TokenResp is a sanatised token instance to return from the controller
type TokenResp struct {
	Name       string
	LastUsed   time.Time
	UsageCount uint
}

// ListTokens lists tokens for a given user
func (totpModule *Controller) ListTokens(userid string) ([]interface{}, error) {
	// Fetch tokens from database
	tokens, err := totpModule.totpStore.GetTotpTokens(userid)
	if err != nil {
		log.Printf("TOTPModule.ListTokens: error fetching TOTP tokens (%s)", err)
		return make([]interface{}, 0), err
	}

	log.Printf("tokens: %+v", tokens)

	cleanTokens := make([]interface{}, len(tokens))
	for i, t := range tokens {
		ti := t.(TokenInterface)
		cleanTokens[i] = &TokenResp{
			Name:       ti.GetName(),
			LastUsed:   ti.GetLastUsed(),
			UsageCount: ti.GetCounter(),
		}
	}

	log.Printf("cleantokens: %+v", cleanTokens)

	return cleanTokens, nil
}
