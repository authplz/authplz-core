package oauth

import (
	"encoding/gob"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
)

import (
	"github.com/gocraft/web"
	"github.com/ory-am/fosite"
	"github.com/ryankurte/authplz/appcontext"
	"golang.org/x/net/context"
)

// APICtx API context instance
type APICtx struct {
	// Base context required by router
	*appcontext.AuthPlzCtx
	// User module instance
	oc *Controller
}

func init() {
	gob.Register(&url.URL{})
	gob.Register(&fosite.Arguments{})
	gob.Register(&fosite.Request{})
	gob.Register(&fosite.AuthorizeRequest{})
	/*
		buf := bytes.NewBuffer([]byte{})

		enc := gob.NewEncoder(buf)
		err := enc.Encode(&fosite.AuthorizeRequest{})

		log.Fatalf("Error %s encoding AuthorizeRequest", err)
	*/
}

// BindOauthContext Helper middleware to bind module controller to API context
func BindOauthContext(oc *Controller) func(ctx *APICtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *APICtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.oc = oc
		next(rw, req)
	}
}

// BindAPI binds the AuditController API to a provided router
func (oc *Controller) BindAPI(router *web.Router) {
	// Create router for user modules
	oauthRouter := router.Subrouter(APICtx{}, "/api/oauth")

	// Attach module context
	oauthRouter.Middleware(BindOauthContext(oc))

	// Bind endpoints
	oauthRouter.Get("/test", (*APICtx).TestGet)
	oauthRouter.Get("/auth", (*APICtx).AuthRequestGet)
	oauthRouter.Get("/pending", (*APICtx).AuthorizePendingGet)
	oauthRouter.Post("/auth", (*APICtx).AuthorizeConfirmPost)
}

// Information endpoint
func (c *APICtx) TestGet(rw web.ResponseWriter, req *web.Request) {
	log.Printf("OAuth2 TestGet called")
	rw.WriteHeader(http.StatusOK)
}

// AuthRequestGet request an authorization instance
func (c *APICtx) AuthRequestGet(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Create context
	ctx := context.Background()

	// Parse authorize request
	authRequest, err := c.oc.OAuth2.NewAuthorizeRequest(ctx, req.Request)
	if err != nil {
		log.Printf("AuthEndpoint NewAuthorizeRequest error: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	authRequestInst := authRequest.(*fosite.AuthorizeRequest)

	authRequestBytes, err := json.Marshal(authRequestInst)
	if err != nil {
		log.Printf("AuthEndpoint NewAuthorizeRequest serialisation error: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Save request to session
	c.GetSession().Values["oauth"] = string(authRequestBytes)
	c.GetSession().Save(req.Request, rw)

	// Return OK
	log.Printf("AuthEndpoint AuthRequestGet success")
	// TODO: this probably needs to redirect to auth ok page for user
	rw.WriteHeader(http.StatusAccepted)
}

type AuthData struct {
	ClientID string
	Scope    string
}

// AuthorizePendingGet Fetch pending authorization
func (c *APICtx) AuthorizePendingGet(rw web.ResponseWriter, req *web.Request) {
	if c.GetSession().Values["oauth"] == nil {
		log.Printf("AuthEndpoint AuthorizePendingGet error: no pending authorization found")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	authRequestString := c.GetSession().Values["oauth"].(string)

	authRequest := fosite.AuthorizeRequest{}
	err := json.Unmarshal([]byte(authRequestString), &authRequest)
	if err != nil {
		log.Printf("AuthEndpoint NewAuthorizeRequest serialisation error: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Printf("AuthEndpoint AuthorizePendingGet ar: %+v", authRequest)

	requestScopes, _ := authRequest.Scopes.Value()

	authData := AuthData{
		authRequest.Client.GetID(),
		requestScopes,
	}

	// Write request to user
	c.WriteJson(rw, authData)
}

// AuthorizeConfirmPost handles auth response from user
func (c *APICtx) AuthorizeConfirmPost(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Load auth request from session
	authRequestString := c.GetSession().Values["oauth"].(string)

	authRequest := fosite.AuthorizeRequest{}
	err := json.Unmarshal([]byte(authRequestString), &authRequest)
	if err != nil {
		log.Printf("AuthEndpoint NewAuthorizeRequest serialisation error: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Create context
	ctx := context.Background()

	// TODO: check for user consent, oauth type & allowed scopes

	// Create session information
	s := fosite.DefaultSession{
		Username: c.GetUserID(),
		Subject:  c.GetUserID(),
	}

	// Generate auth response
	authResponse, err := c.oc.OAuth2.NewAuthorizeResponse(ctx, req.Request, &authRequest, &s)
	if err != nil {
		log.Printf("AuthEndpoint NewAuthorizeResponse error: %s", err)
		c.oc.OAuth2.WriteAuthorizeError(rw, &authRequest, err)
		return
	}

	// Write authorization response
	log.Printf("AuthEndpoint NewAuthorizeRequest success")
	c.oc.OAuth2.WriteAuthorizeResponse(rw, &authRequest, authResponse)
}
