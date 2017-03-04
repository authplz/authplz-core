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

type U2FModule struct {
	url      string
	u2fStore U2FStoreInterface
}

func NewU2FModule(url string, u2fStore U2FStoreInterface) *U2FModule {
	return &U2FModule{
		url:      url,
		u2fStore: u2fStore,
	}
}

// Helper middleware to bind module to API context
func BindU2FContext(u2fModule *U2FModule) func(ctx *U2FApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *U2FApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.um = u2fModule
		next(rw, req)
	}
}

// Bind the API for the coreModule to the provided router
func (u2fModule *U2FModule) BindAPI(router *web.Router) {
	// Create router for user modules
	u2frouter := router.Subrouter(U2FApiCtx{}, "/api/u2f")

	// Attach module context
	u2frouter.Middleware(BindU2FContext(u2fModule))

	// Bind endpoints
	u2frouter.Get("/enrol", 		(*U2FApiCtx).U2FEnrolGet)
	u2frouter.Post("/enrol", 		(*U2FApiCtx).U2FEnrolPost)
	u2frouter.Get("/authenticate", 	(*U2FApiCtx).U2FAuthenticateGet)
	u2frouter.Post("/authenticate", (*U2FApiCtx).U2FAuthenticatePost)
	u2frouter.Get("/tokens", 		(*U2FApiCtx).U2FTokensGet)
}

// Check whether u2f is supported for a given user
// This is required to implement the generic 2fa interface for binding into the core module.
func (u2fModule *U2FModule) IsSupported(userid string) bool {
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

// Fetch a U2F challenge for a given user
func (u2fModule *U2FModule) GetChallenge(userid string) (*u2f.Challenge, error) {

	// Fetch registered tokens
	tokens, err := u2fModule.ListTokens(userid)
	if err != nil {
		log.Printf("U2FModule.GetChallenge: error fetching U2F tokens %s", err)
		return nil, err
	}

	// Convert to u2f objects for usefulness
	var registeredKeys []u2f.Registration
	for _, v := range tokens {
		t := v.(U2FTokenInterface)

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

// Validate and save a u2f registration
// Returns ok, err indicating registration validity and forwarding errors
func (u2fModule *U2FModule) ValidateRegistration(userid, tokenName string, challenge *u2f.Challenge, resp *u2f.RegisterResponse) (bool, error) {

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

func (u2fModule *U2FModule) ValidateSignature(userid string, challenge *u2f.Challenge, resp *u2f.SignResponse) (bool, error) {

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
	var token U2FTokenInterface = nil
	for _, v := range tokens {
		t := v.(U2FTokenInterface)
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

// Add a token to a provided user id
func (u2fModule *U2FModule) AddToken(userid, name, keyHandle, publicKey, certificate string, counter uint) error {
	_, err := u2fModule.u2fStore.AddFidoToken(userid, "", keyHandle, publicKey, certificate, counter)
	if err != nil {
		log.Printf("U2FModule.AddToken: error %s", err)
		return err
	}
	return nil
}

func (u2fModule *U2FModule) UpdateToken() {

}

func (u2fModule *U2FModule) RemoveToken() {

}

func (u2fModule *U2FModule) ListTokens(userid string) ([]interface{}, error) {
	// Fetch tokens from database
	tokens, err := u2fModule.u2fStore.GetFidoTokens(userid)
	if err != nil {
		log.Printf("U2FModule.ListTokens: error fetching U2F tokens (%s)", err)
		return make([]interface{}, 0), err
	}

	return tokens, nil
}
