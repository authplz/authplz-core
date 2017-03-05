/*
 * TOTP Module Controller
 * This defines the TOTP module controller
 *
 * AuthEngine Project (https://github.com/ryankurte/authengine)
 * Copyright 2017 Ryan Kurte
 */

package totp

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"log"

	"github.com/gocraft/web"
	otp "github.com/pquerna/otp/totp"
)

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

	// Bind endpoints
	totpRouter.Get("/enrol", (*totpAPICtx).TOTPEnrolGet)
	totpRouter.Post("/enrol", (*totpAPICtx).TOTPEnrolPost)
	totpRouter.Get("/authenticate", (*totpAPICtx).TOTPAuthenticateGet)
	totpRouter.Post("/authenticate", (*totpAPICtx).TOTPAuthenticatePost)
	totpRouter.Get("/tokens", (*totpAPICtx).TOTPListTokens)
}

// CreateToken creates a TOTP token for the provided account
func (totpModule *Controller) CreateToken(userid string) (string, error) {
	// Generate token
	key, err := otp.Generate(otp.GenerateOpts{
		Issuer:      totpModule.url,
		AccountName: userid,
	})
	if err != nil {
		log.Printf("TOTPModule CreateToken: error generating totp token (%s)", err)
		return "", err
	}

	// Generate image
	img, err := key.Image(200, 200)
	if err != nil {
		log.Printf("TOTPModule CreateToken: error converting token to image(%s)", err)
		return "", err
	}

	// Encode image to buffer
	var buf bytes.Buffer
	png.Encode(&buf, img)

	// Base64 encode image for endpoint
	imgString := base64.StdEncoding.EncodeToString(buf.Bytes())

	return imgString, err
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
		valid := otp.Validate(token, t.(TokenInterface).GetSecret())
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
