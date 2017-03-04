/*
 * TOTP Module Controller
 * This defines the TOTP module controller
 *
 * AuthEngine Project (https://github.com/ryankurte/authengine)
 * Copyright 2017 Ryan Kurte
 */

package totp

import (
	"github.com/gocraft/web"
)

type TOTPModule struct {
	url       string
	totpStore TotpStoreInterface
}

func NewTOTPModule(url string, totpStore TotpStoreInterface) *TOTPModule {
	return &TOTPModule{
		url:       url,
		totpStore: totpStore,
	}
}

// Helper middleware to bind module to API context
func BindU2FContext(totpModule *TOTPModule) func(ctx *TOTPApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *TOTPApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.totpModule = totpModule
		next(rw, req)
	}
}

// Bind the API for the coreModule to the provided router
func (totpModule *TOTPModule) BindAPI(router *web.Router) {
	// Create router for user modules
	totpRouter := router.Subrouter(TOTPApiCtx{}, "/api/totp")

	// Attach module context
	totpRouter.Middleware(BindU2FContext(totpModule))

	// Bind endpoints
	totpRouter.Get("/enrol", (*TOTPApiCtx).TOTPEnrolGet)
	totpRouter.Post("/enrol", (*TOTPApiCtx).TOTPEnrolPost)
	totpRouter.Get("/authenticate", (*TOTPApiCtx).TOTPAuthenticateGet)
	totpRouter.Post("/authenticate", (*TOTPApiCtx).TOTPAuthenticatePost)
	totpRouter.Get("/tokens", (*TOTPApiCtx).TOTPListTokens)
}
