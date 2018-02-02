/*
 * U2F / Fido Module API implementation
 * This provides U2F endpoints for device registration, authentication and management
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

// TODO: move all database operations and things into the controller.

package u2f

import (
	"encoding/gob"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gocraft/web"
	"github.com/ryankurte/go-u2f"

	"github.com/authplz/authplz-core/lib/api"
	"github.com/authplz/authplz-core/lib/appcontext"
)

const (
	u2fRegisterSessionKey   string = "u2f-register-session"
	u2fSignSessionKey       string = "u2f-sign-session"
	u2fRegisterChallengeKey string = "u2f-register-challenge"
	u2fRegisterNameKey      string = "u2f-register-name"
	u2fSignChallengeKey     string = "u2f-sign-challenge"
	u2fSignUserIDKey        string = "u2f-sign-userid"
	u2fSignActionKey        string = "u2f-sign-action"
)

// u2fApiCtx context storage for router instance
type u2fApiCtx struct {
	// Base context for shared components
	*appcontext.AuthPlzCtx

	// U2F controller module
	um *Controller
}

// Initialise serialisation of u2f challenge objects
func init() {
	gob.Register(&u2f.Challenge{})
}

// BindU2FContext Helper middleware to bind module to API context
func BindU2FContext(u2fModule *Controller) func(ctx *u2fApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *u2fApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.um = u2fModule
		next(rw, req)
	}
}

// BindAPI Binds the API for the u2f module to the provided router
func (u2fModule *Controller) BindAPI(router *web.Router) {
	// Create router for user modules
	u2frouter := router.Subrouter(u2fApiCtx{}, "/api/u2f")

	// Attach module context
	u2frouter.Middleware(BindU2FContext(u2fModule))

	// Bind endpoints
	u2frouter.Get("/enrol", (*u2fApiCtx).EnrolGet)
	u2frouter.Post("/enrol", (*u2fApiCtx).EnrolPost)
	u2frouter.Get("/authenticate", (*u2fApiCtx).AuthenticateGet)
	u2frouter.Post("/authenticate", (*u2fApiCtx).AuthenticatePost)
	u2frouter.Get("/tokens", (*u2fApiCtx).TokensGet)
}

// EnrolGet First stage token enrolment (get) handler
// This creates and caches a challenge for a device to be registered
func (c *u2fApiCtx) EnrolGet(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	tokenName := req.URL.Query().Get("name")
	if tokenName == "" {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorNoRequestSession)
		return
	}

	// Build U2F challenge
	challenge, err := c.um.GetChallenge(c.GetUserID())
	if err != nil {
		c.WriteInternalError(rw)
		return
	}
	u2fReq := challenge.RegisterRequest()

	// Save to session
	c.GetSession().Values[u2fRegisterChallengeKey] = challenge
	c.GetSession().Values[u2fRegisterNameKey] = tokenName
	c.GetSession().Save(req.Request, rw)

	log.Println("EnrolGet: Fetched enrolment challenge")

	// Return challenge to user
	c.WriteJSON(rw, *u2fReq)
}

// EnrolPost Second stage token enrolment (post) handler
// This checks the cached challenge and completes device enrolment
func (c *u2fApiCtx) EnrolPost(rw web.ResponseWriter, req *web.Request) {

	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	// Fetch request from session vars
	// TODO: move this to a separate session flash
	if c.GetSession().Values[u2fRegisterChallengeKey] == nil {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorNoRequestSession)
		return
	}
	challenge := c.GetSession().Values[u2fRegisterChallengeKey].(*u2f.Challenge)
	c.GetSession().Values[u2fRegisterChallengeKey] = ""

	keyName := c.GetSession().Values[u2fRegisterNameKey].(string)
	c.GetSession().Values[u2fRegisterNameKey] = ""

	// Parse JSON response body
	var registerResp u2f.RegisterResponse
	jsonErr := json.NewDecoder(req.Body).Decode(&registerResp)
	if jsonErr != nil {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorBadResponse)
		return
	}

	// Validate registration
	ok, err := c.um.ValidateRegistration(c.GetUserID(), keyName, challenge, &registerResp)
	if err != nil {
		c.WriteInternalError(rw)
		return
	}
	if !ok {
		log.Printf("U2F enrolment failed for user %s\n", c.GetUserID())
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorFailed)
		return
	}

	log.Printf("Enrolled U2F token for account %s\n", c.GetUserID())
	c.WriteAPIResult(rw, api.SecondFactorSuccess)
	return
}

// AuthenticateGet Fetches an authentication challenge
// This grabs a pending 2fa userid from the global context
// Not sure how to:
// a) do this better / without global context
// b) allow this to be used for authentication and for "sudo" like behaviour.
func (c *u2fApiCtx) AuthenticateGet(rw web.ResponseWriter, req *web.Request) {
	u2fSession, _ := c.Global.SessionStore.Get(req.Request, u2fSignSessionKey)

	// Fetch challenge user ID
	userid, action := c.Get2FARequest(rw, req)

	if userid == "" {
		log.Printf("u2f.AuthenticateGet No pending 2fa requests found")
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorNoRequestSession)
		return
	}

	log.Printf("u2f.AuthenticateGet Authentication request for user %s (action %s)", userid, action)

	// Generate challenge
	challenge, err := c.um.GetChallenge(userid)
	if err != nil {
		log.Printf("u2f.AuthenticateGet error building u2f challenge %s", err)
		c.WriteInternalError(rw)
		return
	}
	u2fSignReq := challenge.SignRequest()

	// Save to session vars
	u2fSession.Values[u2fSignChallengeKey] = challenge
	u2fSession.Values[u2fSignUserIDKey] = userid
	u2fSession.Values[u2fSignActionKey] = action
	u2fSession.Save(req.Request, rw)

	// Write challenge to user
	c.WriteJSON(rw, *u2fSignReq)
}

// AuthenticatePost Post authentication response to complete authentication
func (c *u2fApiCtx) AuthenticatePost(rw web.ResponseWriter, req *web.Request) {

	u2fSession, _ := c.Global.SessionStore.Get(req.Request, u2fSignSessionKey)

	// Fetch request from session vars
	// TODO: move this to a separate session flash
	if u2fSession.Values[u2fSignChallengeKey] == nil {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorNoRequestSession)
		return
	}
	challenge := u2fSession.Values[u2fSignChallengeKey].(*u2f.Challenge)
	u2fSession.Values[u2fSignChallengeKey] = ""

	if u2fSession.Values[u2fSignUserIDKey] == nil {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorNoRequestSession)
		return
	}
	userid := u2fSession.Values[u2fSignUserIDKey].(string)
	u2fSession.Values[u2fSignUserIDKey] = ""

	action := u2fSession.Values[u2fSignActionKey].(string)
	u2fSession.Values[u2fSignActionKey] = ""

	// Clear session vars
	u2fSession.Save(req.Request, rw)

	log.Printf("u2f.AuthenticatePost for user %s (action %s)", userid, action)

	// Parse JSON response body
	var u2fSignResp u2f.SignResponse
	err := json.NewDecoder(req.Body).Decode(&u2fSignResp)
	if err != nil {
		log.Printf("AuthenticatePost: error decoding sign response (%s)", err)
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.SecondFactorBadResponse)
		return
	}

	// Validate signature
	ok, err := c.um.ValidateSignature(userid, challenge, &u2fSignResp)
	if err != nil {
		c.WriteInternalError(rw)
		return
	}
	if !ok {
		log.Printf("AuthenticatePost: authentication failed for user %s\n", userid)
		c.WriteAPIResultWithCode(rw, http.StatusUnauthorized, api.SecondFactorFailed)
		return
	}

	log.Printf("AuthenticatePost: Valid authentication for account %s (action %s)\n", userid, action)
	c.UserAction(userid, action, rw, req)
	c.WriteAPIResult(rw, api.SecondFactorSuccess)
}

// TokensGet Lists u2f tokens for the logged in user user
func (c *u2fApiCtx) TokensGet(rw web.ResponseWriter, req *web.Request) {

	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	// Fetch tokens
	tokens, err := c.um.ListTokens(c.GetUserID())
	if err != nil {
		log.Printf("u2f.TokensGet error fetching U2F tokens %s", err)
		c.WriteInternalError(rw)
		return
	}

	// Write tokens out
	c.WriteJSON(rw, tokens)
}

// RemoveToken removes a provided token
func (c *u2fApiCtx) RemoveToken(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	// Fetch token ID
	tokenID := req.FormValue("id")
	if tokenID == "" {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.IncorrectArguments)
		return
	}

	// Attempt removal
	ok, err := c.um.RemoveToken(c.GetUserID(), tokenID)
	if err != nil {
		c.WriteInternalError(rw)
		return
	}

	// Write response
	if !ok {
		c.WriteAPIResultWithCode(rw, http.StatusNotFound, api.SecondFactorNotFound)
		return
	}
	c.WriteAPIResult(rw, api.TOTPTokenRemoved)
}
