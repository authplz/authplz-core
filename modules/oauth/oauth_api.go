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
	"encoding/gob"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

import (
	"github.com/gocraft/web"
	"github.com/ory-am/fosite"
	"github.com/ryankurte/authplz/api"
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

func init() {
	// Register AuthorizeRequests for session serialisation
	gob.Register(fosite.AuthorizeRequest{})
	gob.Register(ClientWrapper{})
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
	router.Get("/clients", (*APICtx).ClientsGet)
	router.Post("/clients", (*APICtx).ClientsPost)

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

// ClientsGet Lists clients bound owned by a user account
func (c *APICtx) ClientsGet(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

}

// ClientReq is a client request object used to create an OAuth client
type ClientReq struct {
	Scopes    []string
	Redirects []string
	Grants    []string
	Responses []string
}

// ClientsPost creates a new OAuth client
func (c *APICtx) ClientsPost(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Decode client request
	clientReq := ClientReq{}
	defer req.Body.Close()
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&clientReq); err != nil {
		rw.WriteHeader(http.StatusBadRequest)
	}

	client, err := c.oc.CreateClient(c.GetUserID(), clientReq.Scopes, clientReq.Redirects, clientReq.Grants, clientReq.Responses, true)
	if err != nil {
		c.WriteApiResult(rw, api.ResultError, err.Error())
		return
	}

	c.WriteJson(rw, client)
}

// AuthorizeRequestGet External OAuth authorization endpoint
func (c *APICtx) AuthorizeRequestGet(rw web.ResponseWriter, req *web.Request) {

	// Process authorization request
	ar, err := c.oc.OAuth2.NewAuthorizeRequest(c.fositeContext, req.Request)
	if err != nil {
		c.oc.OAuth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	// Note that checks occur at the AuthorizeConfirmPost stage

	// TODO: Check if app is already authorized and redirect if so (and appropriate)

	// Cache authorization request
	session := c.GetSession()
	session.Values["oauth"] = ar
	session.Save(req.Request, rw)

	// Check user is logged in
	if c.GetUserID() == "" {
		// Bind redirect back and redirect to login page if not
		c.BindRedirect("/oauth/pending", rw, req)
		c.DoRedirect("/login", rw, req)
		return
	}

	// Redirect to pending auth page if logged in
	c.DoRedirect("/oauth/pending", rw, req)

}

// AuthorizePendingGet Fetch pending authorizations for a user
func (c *APICtx) AuthorizePendingGet(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Fetch OAuth Authorization Request from session
	if c.GetSession().Values["oauth"] == nil {
		c.WriteApiResult(rw, api.ResultError, api.ApiMessageEn.NoOAuthPending)
		return
	}
	ar := c.GetSession().Values["oauth"].(fosite.AuthorizeRequest)

	// Client is an interface so cannot be parsed to or from json
	ar.Client = nil

	// Write back to user
	c.WriteJson(rw, &ar)
}

// AuthorizeConfirm authorization confirmation object
type AuthorizeConfirm struct {
	Accept        bool
	State         string
	GrantedScopes []string
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

	// Fetch authorization request from session
	if c.GetSession().Values["oauth"] == nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	ac := AuthorizeConfirm{}
	defer req.Body.Close()
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&ac); err != nil {
		rw.WriteHeader(http.StatusBadRequest)
	}

	ar := c.GetSession().Values["oauth"].(fosite.AuthorizeRequest)

	session := NewSession(c.GetUserID(), "")

	// Validate that granted scopes match those available in AuthorizeRequest
	for _, granted := range ac.GrantedScopes {
		if fosite.HierarchicScopeStrategy(ar.GetRequestedScopes(), granted) {
			ar.GrantedScopes = append(ar.GrantedScopes, granted)
		}
	}

	// Create response
	response, err := c.oc.OAuth2.NewAuthorizeResponse(c.fositeContext, req.Request, &ar, NewSessionWrap(session))
	if err != nil {
		c.oc.OAuth2.WriteAuthorizeError(rw, &ar, err)
		return
	}

	// Write output
	c.oc.OAuth2.WriteAuthorizeResponse(rw, &ar, response)
}

// IntrospectPost Token Introspection endpoint
func (c *APICtx) IntrospectPost(rw web.ResponseWriter, req *web.Request) {

	ctx := fosite.NewContext()
	session := NewSession(c.GetUserID(), "")

	response, err := c.oc.OAuth2.NewIntrospectionRequest(ctx, req.Request, NewSessionWrap(session))
	if err != nil {
		c.oc.OAuth2.WriteIntrospectionError(rw, err)
		return
	}

	c.oc.OAuth2.WriteIntrospectionResponse(rw, response)
}

// AccessTokenInfoGet Access Token Information endpoint
func (c *APICtx) AccessTokenInfoGet(rw web.ResponseWriter, req *web.Request) {

	tokenString := fosite.AccessTokenFromRequest(req.Request)
	if tokenString == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	sig := strings.Split(tokenString, ".")[1]

	token, err := c.oc.GetAccessTokenInfo(sig)
	if err != nil {
		c.WriteApiResult(rw, api.ResultError, err.Error())
		return
	}

	if token == nil {
		c.WriteApiResult(rw, api.ResultError, c.GetApiLocale().NoOAuthTokenFound)
		return
	}

	c.WriteJson(rw, token)
}

// TokenPost Uses an authorization to fetch an access token
func (c *APICtx) TokenPost(rw web.ResponseWriter, req *web.Request) {
	ctx := fosite.NewContext()

	// Create session
	session := NewSession(c.GetUserID(), "")

	session.AccessExpiry = time.Now().Add(time.Hour * 1)
	session.IDExpiry = time.Now().Add(time.Hour * 2)
	session.RefreshExpiry = time.Now().Add(time.Hour * 3)
	session.AuthorizeExpiry = time.Now().Add(time.Hour * 4)

	// Create access request
	ar, err := c.oc.OAuth2.NewAccessRequest(ctx, req.Request, NewSessionWrap(session))
	if err != nil {
		c.oc.OAuth2.WriteAccessError(rw, ar, err)
		return
	}

	// Fetch client from request
	client := ar.(fosite.Requester).GetClient().(*ClientWrapper)

	// Update fields
	client.SetLastUsed(time.Now())

	// Write back to storage
	c.oc.UpdateClient(client.Client)

	// Grant requested scopes
	// TODO: limit by client..?
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	// Build response
	response, err := c.oc.OAuth2.NewAccessResponse(ctx, req.Request, ar)
	if err != nil {
		c.oc.OAuth2.WriteAccessError(rw, ar, err)
		return
	}

	// Write response to client
	c.oc.OAuth2.WriteAccessResponse(rw, ar, response)
}

// TestGet test endpoint
func (c *APICtx) TestGet(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusOK)
}
