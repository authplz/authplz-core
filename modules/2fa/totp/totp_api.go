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
type totpAPICtx struct {
	// Base context for shared components
	*appcontext.AuthPlzCtx

	// U2F controller module
	totpModule *Controller
}

func (c *totpAPICtx) TOTPEnrolGet(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *totpAPICtx) TOTPEnrolPost(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *totpAPICtx) TOTPAuthenticateGet(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *totpAPICtx) TOTPAuthenticatePost(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *totpAPICtx) TOTPListTokens(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}

func (c *totpAPICtx) TOTPRemoveToken(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}
