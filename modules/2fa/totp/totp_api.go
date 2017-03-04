/*
 * TOTP Module API
 * This defines the API methods bound to the TOTP module
 *
 * AuthEngine Project (https://github.com/ryankurte/authengine)
 * Copyright 2017 Ryan Kurte
 */

package totp

import (
	"net/http"
)

import (
	"github.com/gocraft/web"
	//"github.com/ryankurte/authplz/api"
	"github.com/ryankurte/authplz/appcontext"
)

// U2F API context storage
type TOTPApiCtx struct {
	// Base context for shared components
	*appcontext.AuthPlzCtx

	// U2F controller module
	totpModule *TOTPModule
}

func (c *TOTPApiCtx) TOTPEnrolGet(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *TOTPApiCtx) TOTPEnrolPost(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *TOTPApiCtx) TOTPAuthenticateGet(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *TOTPApiCtx) TOTPAuthenticatePost(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *TOTPApiCtx) TOTPListTokens(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *TOTPApiCtx) TOTPRemoveToken(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}
