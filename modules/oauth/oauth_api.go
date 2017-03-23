/*
 * OAuth Module API
 * Provides endpoints for the OAuth module
 *
 * AuthEngine Project (https://github.com/ryankurte/authengine)
 * Copyright 2017 Ryan Kurte
 */

package oauth

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"
)

import (
	"github.com/gocraft/web"
	"github.com/ory-am/fosite"
	"github.com/ryankurte/authplz/appcontext"
)

// APICtx API context instance
type APICtx struct {
	// Base context required by router
	*appcontext.AuthPlzCtx
	// OAuth Controller Instance
	oc *Controller
	// Fosite user context
	fositeContext context.Context
}

// BindOauthContext Helper middleware to bind module controller to API context
func BindOauthContext(oc *Controller) func(ctx *APICtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *APICtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.oc = oc
		next(rw, req)
	}
}

// BindAPI Binds oauth API endpoints to the provded router
func (oc *Controller) BindAPI(base *web.Router) *web.Router {

	// Create router object
	router := base.Subrouter(APICtx{}, "/api/oauth")

	// Bind context to router
	router.Middleware(BindOauthContext(oc))

	// Bind paths to endpoint
	router.Get("/auth", (*APICtx).AuthorizeRequestGet)
	router.Get("/pending", (*APICtx).AuthorizePendingGet)
	router.Post("/auth", (*APICtx).AuthorizeConfirmPost)

	router.Post("/token", (*APICtx).TokenPost)
	router.Get("/introspect", (*APICtx).IntrospectPost)
	router.Get("/test", (*APICtx).TestGet)

	router.Get("/info", (*APICtx).AccessTokenInfoGet)

	// Return router for external use
	return router
}

// AuthorizeRequestGet External OAuth authorization endpoint
func (c *APICtx) AuthorizeRequestGet(rw web.ResponseWriter, req *web.Request) {

	log.Printf("AuthorizeRequestGet\n")

	// Check user is logged in
	if c.GetUserID() == "" {
		// TODO: Redirect if not
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Process authorization request
	ar, err := c.oc.OAuth2.NewAuthorizeRequest(c.fositeContext, req.Request)
	if err != nil {
		log.Printf("OAUTH NewAuthorizeRequest error: %s\n", err)
		c.oc.OAuth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	log.Printf("Authentication req: %+v\n", ar)
	log.Printf("Response Types: %+v\n", ar.GetResponseTypes())
	log.Printf("Scopes: %+v\n", ar.GetRequestedScopes())

	// TODO: Check user authorization?

	// TODO: Check scopes
	// Fail if invalid

	// TODO: Check if app is already authorized
	// Redirect if so (and appropriate)

	// Cache authorization request
	c.GetSession().Values["oauth"] = ar
	c.GetSession().Save(req.Request, rw)

	// TODO: Redirect to user authorization if not
	rw.WriteHeader(http.StatusOK)
}

// AuthorizePendingGet Fetch pending authorizations for a user
func (c *APICtx) AuthorizePendingGet(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	if c.GetSession().Values["oauth"] == nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	ar := c.GetSession().Values["oauth"].(fosite.AuthorizeRequest)

	c.WriteJson(rw, ar)
}

// AuthorizeConfirmPost Confirm authorization of a token
// This finalises and stores the authentication, and redirects back to the calling service
// TODO: this endpoint /really/ needs CSRF / CORS protection
func (c *APICtx) AuthorizeConfirmPost(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Fetch authorization request
	if c.GetSession().Values["oauth"] == nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	ar := c.GetSession().Values["oauth"].(fosite.AuthorizeRequest)

	session := NewSession(c.GetUserID(), "")

	// TODO: Validate authorization
	//granted := c.oc.ValidateScopes(ar.GetRequestedScopes)

	// TODO: Create Grants

	// Create response
	response, err := c.oc.OAuth2.NewAuthorizeResponse(c.fositeContext, req.Request, &ar, NewSessionWrap(session))
	if err != nil {
		log.Printf("OAUTH NewAuthorizeResponse error: %s\n", err)
		c.oc.OAuth2.WriteAuthorizeError(rw, &ar, err)
		return
	}

	// Write output
	c.oc.OAuth2.WriteAuthorizeResponse(rw, &ar, response)
}

// Introspection endpoint
func (c *APICtx) IntrospectPost(rw web.ResponseWriter, req *web.Request) {

	ctx := fosite.NewContext()
	session := NewSession(c.GetUserID(), "")

	response, err := c.oc.OAuth2.NewIntrospectionRequest(ctx, req.Request, NewSessionWrap(session))
	if err != nil {
		log.Printf("OAUTH IntrospectionRequest error: %s\n", err)
		c.oc.OAuth2.WriteIntrospectionError(rw, err)
		return
	}

	c.oc.OAuth2.WriteIntrospectionResponse(rw, response)
}

// AccessTokenInfoGet Access Token Information endpoint
func (c *APICtx) AccessTokenInfoGet(rw web.ResponseWriter, req *web.Request) {

	log.Printf("Information get")

	tokenString := fosite.AccessTokenFromRequest(req.Request)
	if tokenString == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	log.Printf("Token string: %s", tokenString)
	sig := strings.Split(tokenString, ".")[1]

	token, err := c.oc.GetAccessTokenInfo(sig)
	if err != nil {
		log.Printf("OAuthAPI InfoGet GetAccessToken error: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if token == nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	c.WriteJson(rw, token)
}

// TokenPost Uses an authorization to fetch an access token
func (c *APICtx) TokenPost(rw web.ResponseWriter, req *web.Request) {
	ctx := fosite.NewContext()

	log.Printf("Access Token Request")

	// Create session
	session := NewSession(c.GetUserID(), "")

	session.AccessExpiry = time.Now().Add(time.Hour * 1)
	session.IDExpiry = time.Now().Add(time.Hour * 2)
	session.RefreshExpiry = time.Now().Add(time.Hour * 3)
	session.AuthorizeExpiry = time.Now().Add(time.Hour * 4)

	// Create access request
	ar, err := c.oc.OAuth2.NewAccessRequest(ctx, req.Request, NewSessionWrap(session))
	if err != nil {
		log.Printf("OAUTH NewAccessRequest error: %s\n", err)
		c.oc.OAuth2.WriteAccessError(rw, ar, err)
		return
	}

	// Fetch client from request
	client := ar.(fosite.Requester).GetClient().(*ClientWrapper)

	// Update fields
	client.SetLastUsed(time.Now())

	// TODO: Write back to storage
	//c.oc.UpdateClient(client.Client)

	// Grant requested scopes
	// TODO: limit by client..?
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	// Build response
	response, err := c.oc.OAuth2.NewAccessResponse(ctx, req.Request, ar)
	if err != nil {
		log.Printf("OAUTH NewAccessResponse error: %s\n", err)
		c.oc.OAuth2.WriteAccessError(rw, ar, err)
		return
	}

	log.Printf("Access response: %+v", response)

	// Write response to client
	c.oc.OAuth2.WriteAccessResponse(rw, ar, response)
}

// TestGet test endpoint
func (c *APICtx) TestGet(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusOK)
}
