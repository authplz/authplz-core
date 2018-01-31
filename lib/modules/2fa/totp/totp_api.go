/*
 * TOTP Module API
 * This defines the API methods bound to the TOTP module
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
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

	"github.com/authplz/authplz-core/lib/api"
	"github.com/authplz/authplz-core/lib/appcontext"
	"github.com/gocraft/web"
	"github.com/gorilla/sessions"
	"github.com/pquerna/otp"
)

//"github.com/authplz/authplz-core/lib/api"

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
func totpSessionMiddleware(c *totpAPICtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	totpSession, err := c.Global.SessionStore.Get(req.Request, totpSessionKey)
	if err != nil {
		log.Printf("TOTPSessionMiddlware: error fetching %s  (%s)", totpSessionKey, err)

		// Invalidate existing session
		totpSession.Options.MaxAge = -1
		totpSession.Save(req.Request, rw)

		// Write error code
		c.WriteInternalError(rw)
		return
	}
	// Bind session instance
	c.totpSession = totpSession
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
		c.WriteUnauthorized(rw)
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
		c.WriteInternalError(rw)
		return
	}

	// Build Image
	var buf bytes.Buffer
	img, err := token.Image(200, 200)
	if err != nil {
		log.Printf("TOTPEnrolGet: error creating token image (%s)", err)
		c.WriteInternalError(rw)
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
	c.WriteJSON(rw, &resp)
}

// TOTPEnrolPost checks a totp code against the session stored TOTP token and enrols the token on success
func (c *totpAPICtx) TOTPEnrolPost(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteAPIResultWithCode(rw, http.StatusUnauthorized, api.Unauthorized)
		return
	}

	// Fetch session variables
	if c.totpSession.Values[totpRegisterTokenKey] == nil {
		log.Printf("TOTPEnrolPost: missing session variables (%s)", totpRegisterTokenKey)
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorNoRequestSession)
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
	code := req.FormValue("code")

	valid, err := c.totpModule.ValidateRegistration(c.GetUserID(), keyName, token.Secret(), code)
	if err != nil {
		log.Printf("TOTPEnrolPost: error validating token registration (%s)", err)
		c.WriteAPIResultWithCode(rw, http.StatusInternalServerError, api.InternalError)
		return
	}

	if !valid {
		log.Printf("TOTPEnrolPost: validation failed with invalid token (%s)", err)
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorFailed)
		return
	}

	log.Printf("TOTPEnrolPost: enrolled token for user %s", c.GetUserID())
	c.WriteAPIResult(rw, api.SecondFactorSuccess)
}

// TOTPAuthenticatePost completes a totp authentication
func (c *totpAPICtx) TOTPAuthenticatePost(rw web.ResponseWriter, req *web.Request) {

	// Fetch challenge user ID
	userid, action := c.Get2FARequest(rw, req)
	if userid == "" {
		log.Printf("totp.TOTPAuthenticatePost No pending 2fa requests found")
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorNoRequestSession)
		return
	}

	log.Printf("totp.TOTPAuthenticatePost Authentication request for user %s", userid)

	// Fetch challenge code
	code := req.FormValue("code")

	ok, err := c.totpModule.ValidateToken(userid, code)
	if err != nil {
		log.Printf("TOTPAuthenticatePost: error validating totp code (%s)", err)
		c.WriteInternalError(rw)
		return
	}

	if !ok {
		log.Printf("TOTPAuthenticatePost: authentication failed for user %s\n", userid)
		c.WriteAPIResultWithCode(rw, http.StatusUnauthorized, api.SecondFactorFailed)
		return
	}

	log.Printf("TOTPAuthenticatePost: Valid authentication for account %s (action %s)\n", userid, action)
	c.UserAction(userid, action, rw, req)

	c.WriteAPIResult(rw, api.SecondFactorSuccess)
}

// TOTPListTokens lists sanatised totp tokens for a given account
func (c *totpAPICtx) TOTPListTokens(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	// Fetch tokens
	tokens, err := c.totpModule.ListTokens(c.GetUserID())
	if err != nil {
		log.Printf("Error fetching TOTP tokens %s", err)
		c.WriteInternalError(rw)
		return
	}

	// Write tokens out
	c.WriteJSON(rw, tokens)
}

// TOTPRemoveToken removes a provided token
func (c *totpAPICtx) TOTPRemoveToken(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteAPIResultWithCode(rw, http.StatusUnauthorized, api.Unauthorized)
		return
	}

	// Fetch token ID
	tokenID := req.FormValue("id")
	if tokenID == "" {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.IncorrectArguments)
		return
	}

	// Attempt removal
	ok, err := c.totpModule.RemoveToken(c.GetUserID(), tokenID)
	if err != nil {
		c.WriteInternalError(rw)
		return
	}

	// Write response
	if !ok {
		c.WriteAPIResultWithCode(rw, http.StatusNotFound, api.IncorrectArguments)
		return
	}
	c.WriteAPIResult(rw, api.TOTPTokenRemoved)
}
