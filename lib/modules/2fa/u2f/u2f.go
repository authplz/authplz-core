/*
 * U2F / Fido Module Controller implementation
 * This provides a 2fa interface for binding into the core module as well as helpers to
 * create and bind a router to the server instance.
 *
 * AuthEngine Project (https://github.com/ryankurte/authengine)
 * Copyright 2017 Ryan Kurte
 */

package u2f

import (
	"log"
	"time"
)

import (
	"github.com/gocraft/web"
	u2f "github.com/ryankurte/go-u2f"
)

// Controller U2F controller instance storage
type Controller struct {
	url      string
	u2fStore Storer
}

// NewController creates a new U2F controller
// TOTP tokens are issued against the provided url, the browser will reject any u2f requess not from this domain.
// A CompletedHandler is required for completion of authorization actions, as well as a Storer to
// provide underlying storage to the U2F module
func NewController(url string, u2fStore Storer) *Controller {
	return &Controller{
		url:      url,
		u2fStore: u2fStore,
	}
}

// BindU2FContext Helper middleware to bind module to API context
func BindU2FContext(u2fModule *Controller) func(ctx *apiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *apiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.um = u2fModule
		next(rw, req)
	}
}

// BindAPI Binds the API for the u2f module to the provided router
func (u2fModule *Controller) BindAPI(router *web.Router) {
	// Create router for user modules
	u2frouter := router.Subrouter(apiCtx{}, "/api/u2f")

	// Attach module context
	u2frouter.Middleware(BindU2FContext(u2fModule))

	// Bind endpoints
	u2frouter.Get("/enrol", (*apiCtx).U2FEnrolGet)
	u2frouter.Post("/enrol", (*apiCtx).U2FEnrolPost)
	u2frouter.Get("/authenticate", (*apiCtx).U2FAuthenticateGet)
	u2frouter.Post("/authenticate", (*apiCtx).U2FAuthenticatePost)
	u2frouter.Get("/tokens", (*apiCtx).U2FTokensGet)
}

// IsSupported Checks whether u2f is supported for a given user by userid
// This is required to implement the generic 2fa interface for binding into the core module.
func (u2fModule *Controller) IsSupported(userid string) bool {
	tokens, err := u2fModule.u2fStore.GetFidoTokens(userid)
	if err != nil {
		log.Printf("U2FModule.IsSupported error fetching fido tokens for user %s (%s)", userid, tokens)
		return false
	}
	if len(tokens) == 0 {
		return false
	}
	return true
}

// GetChallenge Fetches a U2F challenge for a given user
func (u2fModule *Controller) GetChallenge(userid string) (*u2f.Challenge, error) {

	// Fetch registered tokens
	tokens, err := u2fModule.ListTokens(userid)
	if err != nil {
		log.Printf("U2FModule.GetChallenge: error fetching U2F tokens %s", err)
		return nil, err
	}

	// Convert to u2f objects for usefulness
	var registeredKeys []u2f.Registration
	for _, v := range tokens {
		t := v.(TokenInterface)

		reg := u2f.Registration{
			KeyHandle:   t.GetKeyHandle(),
			PublicKey:   t.GetPublicKey(),
			Certificate: t.GetCertificate(),
			Counter:     t.GetCounter(),
		}
		registeredKeys = append(registeredKeys, reg)
	}

	// Create challenge object
	challenge, _ := u2f.NewChallenge(u2fModule.url, []string{u2fModule.url}, registeredKeys)

	return challenge, nil
}

// ValidateRegistration Validates and saves a u2f registration
// Returns ok, err indicating registration validity and forwarding errors
func (u2fModule *Controller) ValidateRegistration(userid, tokenName string, challenge *u2f.Challenge, resp *u2f.RegisterResponse) (bool, error) {

	// Check registration validity
	// TODO: attestation should be disabled only in test mode, need a better certificate list
	reg, err := challenge.Register(*resp, &u2f.RegistrationConfig{SkipAttestationVerify: true})
	if err != nil {
		log.Printf("U2FModule.ValidateRegistration: challenge validation failed (%s)", err)
		return false, nil
	}

	// Create and save token
	_, err = u2fModule.u2fStore.AddFidoToken(userid, tokenName, reg.KeyHandle, reg.PublicKey, reg.Certificate, reg.Counter)
	if err != nil {
		log.Printf("U2FModule.ValidateRegistration: error storing registration (%s)", err)
		return false, err
	}

	// Indicate successful registration
	return true, nil
}

// ValidateSignature validates a u2f signature response
func (u2fModule *Controller) ValidateSignature(userid string, challenge *u2f.Challenge, resp *u2f.SignResponse) (bool, error) {

	// Check signature validity
	reg, err := challenge.Authenticate(*resp)
	if err != nil {
		log.Printf("U2FModule.ValidateSignature: challenge validation failed (%s)", err)
		return false, nil
	}

	// Fetch registered tokens
	tokens, err := u2fModule.ListTokens(userid)
	if err != nil {
		log.Printf("U2FModule.GetChallenge: error fetching U2F tokens %s", err)
		return false, err
	}

	// Locate matching token
	var token TokenInterface
	for _, v := range tokens {
		t := v.(TokenInterface)
		if t.GetKeyHandle() == reg.KeyHandle {
			token = t
		}
	}
	if token == nil {
		log.Printf("U2FModule.ValidateSignature: matching U2F token not found for user %s", userid)
		return false, nil
	}

	// Update token instance
	token.SetCounter(reg.Counter)
	token.SetLastUsed(time.Now())

	// Save updated token
	_, err = u2fModule.u2fStore.UpdateFidoToken(token)
	if err != nil {
		log.Printf("U2FModule.ValidateSignature: error updating token object (%s)", err)
		return false, err
	}

	// Indicate successful authentication
	return true, nil
}

// AddToken Adds a token to a provided user id
func (u2fModule *Controller) AddToken(userid, name, keyHandle, publicKey, certificate string, counter uint) error {
	_, err := u2fModule.u2fStore.AddFidoToken(userid, "", keyHandle, publicKey, certificate, counter)
	if err != nil {
		log.Printf("U2FModule.AddToken: error %s", err)
		return err
	}
	return nil
}

// UpdateToken Updates a token instance
// TODO: not sure if/why this is required atm
func (u2fModule *Controller) UpdateToken() {

}

// RemoveToken Removes a token instance
func (u2fModule *Controller) RemoveToken() {

}

// ListTokens lists tokens for a given user
func (u2fModule *Controller) ListTokens(userid string) ([]interface{}, error) {
	// Fetch tokens from database
	tokens, err := u2fModule.u2fStore.GetFidoTokens(userid)
	if err != nil {
		log.Printf("U2FModule.ListTokens: error fetching U2F tokens (%s)", err)
		return make([]interface{}, 0), err
	}

	return tokens, nil
}
