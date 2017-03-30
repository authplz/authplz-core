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
	"encoding/gob"

	"github.com/gocraft/web"
	"github.com/gorilla/sessions"
	"github.com/pquerna/otp"
	"github.com/ryankurte/authplz/lib/api"
	"github.com/ryankurte/authplz/lib/appcontext"
)

//"github.com/ryankurte/authplz/lib/api"

// U2F API context storage
type totpAPICtx struct {
	// Base context for shared components
	*appcontext.AuthPlzCtx

	// TOTP controller module
	totpModule *Controller

	// totp session
	totpSession *sessions.Session
}

func init() {
	gob.Register(&otp.Key{})
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

// RegisterChallenge is a TOTP registration challenge
type RegisterChallenge struct {
	AccountName string
	Issuer      string
	TokenName   string
	URL         string
	Image       string
	Secret      string
}

// TOTPEnrolGet Fetches a challenge for TOTP enrolment and saves this to the totp session storage
func (c *totpAPICtx) TOTPEnrolGet(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
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
	resp := RegisterChallenge{token.AccountName(), token.Issuer(), tokenName, token.String(), b64Image, token.Secret()}

	// Save token to session
	c.totpSession.Values[totpRegisterTokenKey] = token.String()
	c.totpSession.Values[totpRegisterNameKey] = tokenName
	c.totpSession.Save(req.Request, rw)

	log.Printf("Session A: %+v", c.totpSession)

	log.Println("TOTPEnrolGet: Fetched enrolment challenge")

	// Return response
	c.WriteJson(rw, &resp)
}

// TOTPEnrolPost checks a totp code against the session stored TOTP token and enrols the token on success
func (c *totpAPICtx) TOTPEnrolPost(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteApiResult(rw, api.ResultError, c.GetApiLocale().Unauthorized)
		return
	}

	// Fetch session variables
	if c.totpSession.Values[totpRegisterTokenKey] == nil {
		log.Printf("TOTPEnrolPost: missing session variables (%s)", totpRegisterTokenKey)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenString := c.totpSession.Values[totpRegisterTokenKey].(string)
	c.totpSession.Values[totpRegisterTokenKey] = ""

	keyName := c.totpSession.Values[totpRegisterNameKey].(string)
	c.totpSession.Values[totpRegisterNameKey] = ""

	c.totpSession.Save(req.Request, rw)

	token, _ := otp.NewKeyFromURL(tokenString)

	// Fetch challenge code from post request
	req.ParseForm()
	code := req.Form.Get("code")

	valid, err := c.totpModule.ValidateRegistration(c.GetUserID(), keyName, token.Secret(), code)
	if err != nil {
		log.Printf("TOTPEnrolPost: error validating token registration (%s)", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if !valid {
		log.Printf("TOTPEnrolPost: validation failed with invalid token (%s)", err)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	log.Printf("TOTPEnrolPost: enrolled token for user %s", c.GetUserID())
	rw.WriteHeader(http.StatusOK)
}

func (c *totpAPICtx) TOTPAuthenticatePost(rw web.ResponseWriter, req *web.Request) {

	// Fetch challenge user ID
	userid, action := c.Get2FARequest(rw, req)
	if userid == "" {
		log.Printf("totp.TOTPAuthenticatePost No pending 2fa requests found")
		c.WriteApiResult(rw, api.ResultError, c.GetApiLocale().InternalError)
		return
	}

	log.Printf("totp.TOTPAuthenticatePost Authentication request for user %s", userid)

	// Fetch challenge code
	req.ParseForm()
	code := req.Form.Get("code")

	ok, err := c.totpModule.ValidateToken(userid, code)
	if err != nil {
		log.Printf("TOTPAuthenticatePost: error validating totp code (%s)", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if !ok {
		log.Printf("TOTPAuthenticatePost: authentication failed for user %s\n", userid)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	log.Printf("TOTPAuthenticatePost: Valid authentication for account %s (action %s)\n", userid, action)
	c.UserAction(userid, action, rw, req)
	rw.WriteHeader(http.StatusOK)
}

func (c *totpAPICtx) TOTPListTokens(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Fetch tokens
	tokens, err := c.totpModule.ListTokens(c.GetUserID())
	if err != nil {
		log.Printf("Error fetching TOTP tokens %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Write tokens out
	c.WriteJson(rw, tokens)
}

func (c *totpAPICtx) TOTPRemoveToken(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusNotImplemented)
}
