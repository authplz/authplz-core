package u2f

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)
import (
	"github.com/gocraft/web"
	"github.com/ryankurte/go-u2f"

	"github.com/ryankurte/authplz/api"
	"github.com/ryankurte/authplz/appcontext"
)

type U2FApiCtx struct {
	// Base context for shared components
	*appcontext.AuthPlzCtx

	// U2F controller module
	um *U2FModule
}

func init() {
	gob.Register(&u2f.Challenge{})
}

// First stage token enrolment (get) handler
// This creates and caches a challenge for a device to be registered
func (c *U2FApiCtx) U2FEnrolGet(rw web.ResponseWriter, req *web.Request) {
	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().Unauthorized)
		return
	}

	tokenName := req.URL.Query().Get("name")
	if tokenName == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	//TODO: get existing keys
	var registeredKeys []u2f.Registration

	// Build U2F challenge
	challenge, _ := u2f.NewChallenge(c.um.url, []string{c.um.url}, registeredKeys)
	u2fReq := challenge.RegisterRequest()

	c.GetSession().Values["u2f-register-challenge"] = challenge
	c.GetSession().Values["u2f-register-name"] = tokenName
	c.GetSession().Save(req.Request, rw)

	log.Println("U2FEnrolGet: Fetched enrolment challenge")

	c.WriteJson(rw, *u2fReq)
}

// Second stage token enrolment (post) handler
// This checks the cached challenge and completes device enrolment
func (c *U2FApiCtx) U2FEnrolPost(rw web.ResponseWriter, req *web.Request) {

	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().Unauthorized)
		return
	}

	// Fetch request from session vars
	// TODO: move this to a separate session flash
	if c.GetSession().Values["u2f-register-challenge"] == nil {
		c.WriteApiResult(rw, api.ApiResultError, "No challenge found")
		fmt.Println("No challenge found in session flash")
		return
	}
	challenge := c.GetSession().Values["u2f-register-challenge"].(*u2f.Challenge)
	c.GetSession().Values["u2f-register-challenge"] = ""

	// Parse JSON response body
	var u2fResp u2f.RegisterResponse
	jsonErr := json.NewDecoder(req.Body).Decode(&u2fResp)
	if jsonErr != nil {
		c.WriteApiResult(rw, api.ApiResultError, "Invalid U2F registration response")
		return
	}

	// Check registration validity
	// TODO: attestation should be disabled only in test mode, need a better certificate list
	reg, err := challenge.Register(u2fResp, &u2f.RegistrationConfig{SkipAttestationVerify: true})
	if err != nil {
		// Registration failed.
		log.Println(err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().U2FRegistrationFailed)
		return
	}

	// Create and save token
	// TODO: add token name
	_, err = c.um.u2fStore.AddFidoToken(c.GetUserID(), "", reg.KeyHandle, reg.PublicKey, reg.Certificate, reg.Counter)
	if err != nil {
		// Registration failed.
		log.Println(err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return
	}

	log.Printf("Enrolled U2F token for account %s\n", c.GetUserID())
	c.WriteApiResult(rw, api.ApiResultOk, c.GetApiLocale().U2FRegistrationComplete)
}

func (c *U2FApiCtx) U2FAuthenticateGet(rw web.ResponseWriter, req *web.Request) {
	u2fSession, err := c.Global.SessionStore.Get(req.Request, "u2f-sign-session")
	if err != nil {
		log.Printf("Error fetching u2f-sign-session 3  %s", err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return
	}

	// Fetch challenge user ID
	userid := c.Get2FARequest(rw, req)

	if userid == "" {
		log.Printf("u2f.U2FAuthenticateGet No pending 2fa requests found")
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return
	}

	log.Printf("U2F Authenticate request for user %s", userid)

	// Fetch existing keys
	tokens, err := c.um.u2fStore.GetFidoTokens(userid)
	if err != nil {
		log.Printf("Error fetching U2F tokens %s", err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return
	}

	//Coerce to U2F types
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

	// Build U2F challenge
	challenge, err := u2f.NewChallenge(c.um.url, []string{c.um.url}, registeredKeys)
	if err != nil {
		log.Printf("Error creating U2F sign request %s", err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return
	}

	u2fSignReq := challenge.SignRequest()

	u2fSession.Values["u2f-sign-challenge"] = challenge
	u2fSession.Save(req.Request, rw)

	c.WriteJson(rw, *u2fSignReq)
}

func (c *U2FApiCtx) U2FAuthenticatePost(rw web.ResponseWriter, req *web.Request) {

	u2fSession, err := c.Global.SessionStore.Get(req.Request, "u2f-sign-session")
	if err != nil {
		log.Printf("Error fetching u2f-sign-session 3  %s", err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return
	}

	// Fetch request from session vars
	// TODO: move this to a separate session flash
	if u2fSession.Values["u2f-sign-challenge"] == nil {
		c.WriteApiResult(rw, api.ApiResultError, "No challenge found")
		fmt.Println("No challenge found in session flash")
		return
	}
	challenge := u2fSession.Values["u2f-sign-challenge"].(*u2f.Challenge)
	u2fSession.Values["u2f-sign-challenge"] = ""

	if u2fSession.Values["u2f-sign-userid"] == nil {
		c.WriteApiResult(rw, api.ApiResultError, "No userid found")
		fmt.Println("No userid found in session flash")
		return
	}
	userid := u2fSession.Values["u2f-sign-userid"].(string)
	u2fSession.Values["u2f-sign-userid"] = ""

	u2fSession.Save(req.Request, rw)

	// Parse JSON response body
	var u2fSignResp u2f.SignResponse
	jsonErr := json.NewDecoder(req.Body).Decode(&u2fSignResp)
	if jsonErr != nil {
		c.WriteApiResult(rw, api.ApiResultError, "Invalid U2F registration response")
		return
	}

	// Fetch user object
	u, err := c.um.u2fStore.GetUserByExtId(userid)
	if err != nil {
		log.Println(err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return
	}

	// Check signature validity
	reg, err := challenge.Authenticate(u2fSignResp)
	if err != nil {
		// Registration failed.
		log.Println(err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().U2FRegistrationFailed)
		return
	}

	// Fetch existing keys
	tokens, err := c.um.u2fStore.GetFidoTokens(userid)
	if err != nil {
		log.Printf("Error fetching U2F tokens %s", err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return
	}

	// Match with registration token
	var token U2FTokenInterface = nil
	for _, v := range tokens {
		t := v.(U2FTokenInterface)
		if t.GetKeyHandle() == reg.KeyHandle {
			token = t
		}
	}
	if token == nil {
		log.Printf("Matching U2F token not found")
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().NoU2FTokenFound)
		return
	}

	// Update token counter / last used
	token.SetCounter(reg.Counter)
	token.SetLastUsed(time.Now())

	// Save updated token against user
	_, err = c.um.u2fStore.UpdateFidoToken(token)
	if err != nil {
		// Registration failed.
		log.Println(err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return
	}

	log.Printf("Valid U2F login for account %s\n", userid)
	c.LoginUser(u.(appcontext.User), rw, req)
	c.WriteApiResult(rw, api.ApiResultOk, c.GetApiLocale().LoginSuccessful)
}

func (c *U2FApiCtx) U2FTokensGet(rw web.ResponseWriter, req *web.Request) {

	// Check if user is logged in
	if c.GetUserID() == "" {
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().Unauthorized)
		return
	}

	tokens, err := c.um.u2fStore.GetFidoTokens(c.GetUserID())
	if err != nil {
		log.Printf("Error fetching U2F tokens %s", err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return
	}

	c.WriteJson(rw, tokens)
}
