package oauth

import (
	"log"
	"net/http"
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
	oauthRouter.Get("/auth", (*APICtx).AuthRequestGet)
	oauthRouter.Get("/pending", (*APICtx).AuthorizePendingGet)
	oauthRouter.Post("/auth", (*APICtx).AuthorizeConfirmPost)
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
		c.oc.OAuth2.WriteAuthorizeError(rw, authRequest, err)
		return
	}

	// Save request to session
	c.GetSession().Values["oauth"] = authRequest
	c.GetSession().Save(req.Request, rw)

	// Return OK
	// TODO: this probably needs to redirect to auth ok page for user
	rw.WriteHeader(http.StatusAccepted)
}

// AuthorizePendingGet Fetch pending authorization
func (c *APICtx) AuthorizePendingGet(rw web.ResponseWriter, req *web.Request) {
	if c.GetSession().Values["oauth"] == nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	ar := c.GetSession().Values["oauth"].(fosite.AuthorizeRequest)

	requestScopes, _ := ar.Scopes.Value()

	authData := struct {
		ClientID string
		Scope    string
	}{
		ar.Client.GetID(),
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
	authRequest := c.GetSession().Values["oauth"].(fosite.AuthorizeRequest)

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
