/*
 * TOTP Module API
 * This defines the API methods bound to the TOTP module
 *
 * AuthEngine Project (https://github.com/ryankurte/authengine)
 * Copyright 2017 Ryan Kurte
 */

package totp

import (
	"bytes"
	"image/png"
	"log"
	"net/http"

	"encoding/base64"

	"github.com/gocraft/web"
	"github.com/gorilla/sessions"
	"github.com/ryankurte/authplz/api"
	"github.com/ryankurte/authplz/appcontext"
)

//"github.com/ryankurte/authplz/api"

// U2F API context storage
type totpAPICtx struct {
	// Base context for shared components
	*appcontext.AuthPlzCtx

	// TOTP controller module
	totpModule *Controller

	// totp session
	totpSession *sessions.Session
}

const (
	totpSessionKey       string = "totp-session"
	totpRegisterTokenKey string = "totp-register-token"
	totpRegisterNameKey  string = "totp-register-name"
)

// Session middleware to retrieve a totp session from a request
func totpSessionMiddleware(ctx *totpAPICtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	totpSession, err := ctx.Global.SessionStore.Get(req.Request, totpSessionKey)
	if err != nil {
		log.Printf("TOTPSessionMiddlware: error fetching %s  (%s)", totpSessionKey, err)

		// Invalidate existing session
		totpSession.Options.MaxAge = -1
		totpSession.Save(req.Request, rw)

		// Write error code
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Bind session instance
	ctx.totpSession = totpSession
	next(rw, req)
}

type totpEnrolment struct {
	Name  string
	URL   string
	Image string
}

func (c *totpAPICtx) TOTPEnrolGet(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().Unauthorized)
		return
	}

	// Fetch a name for the token
	tokenName := req.URL.Query().Get("name")
	if tokenName == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Generate a token
	token, err := c.totpModule.CreateToken(c.GetUserID())
	if err != nil {
		log.Printf("TOTPEnrolGet: error creating token (%s)", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Build Image
	var buf bytes.Buffer
	img, err := token.Image(200, 200)
	if err != nil {
		log.Printf("TOTPEnrolGet: error creating token image (%s)", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Encode image as base64
	png.Encode(&buf, img)
	b64Image := base64.StdEncoding.EncodeToString(buf.Bytes())

	// Create response structure
	resp := totpEnrolment{tokenName, token.String(), b64Image}

	// Save token to session
	c.totpSession.Values[totpRegisterTokenKey] = token
	c.totpSession.Values[totpRegisterNameKey] = tokenName
	c.totpSession.Save(req.Request, rw)

	log.Println("TOTPEnrolGet: Fetched enrolment challenge")

	// Return response
	c.WriteJson(rw, &resp)
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
