/*
 * OAuth Module API
 * Provides endpoints for the OAuth module
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package oauth

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/gocraft/web"
	"github.com/ory/fosite"
	"github.com/pkg/errors"

	"github.com/authplz/authplz-core/lib/api"
	"github.com/authplz/authplz-core/lib/appcontext"
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
	router.Get("/options", (*APICtx).OptionsGet)
	router.Post("/clients", (*APICtx).ClientsPost)

	router.Get("/auth", (*APICtx).AuthorizeRequestGet)
	router.Get("/pending", (*APICtx).AuthorizePendingGet)
	router.Post("/auth", (*APICtx).AuthorizeConfirmPost)

	router.Post("/token", (*APICtx).TokenPost)
	router.Get("/introspect", (*APICtx).IntrospectPost)
	router.Get("/test", (*APICtx).TestGet)

	router.Get("/info", (*APICtx).AccessTokenInfoGet)

	router.Get("/sessions", (*APICtx).SessionsInfoGet)

	// Return router for external use
	return router
}

// ClientsGet Lists clients bound owned by a user account
func (c *APICtx) ClientsGet(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	// TODO: should admins be able to view all clients?

	clients, err := c.oc.GetClients(c.GetUserID())
	if err != nil {
		log.Printf("oauth.CliensGet error fetching oauth clients %s", err)
		c.WriteInternalError(rw)
		return
	}

	c.WriteJSON(rw, clients)
}

// OptionsGet fetch OAuth client options
func (c *APICtx) OptionsGet(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	// TODO: isAdmin filter here
	options, err := c.oc.GetOptions(c.GetUserID())
	if err != nil {
		log.Printf("oauth.CliensGet error error fetching OAuth options %s", err)
		c.WriteInternalError(rw)
		return
	}

	c.WriteJSON(rw, options)
}

// ClientReq is a client request object used to create an OAuth client
type ClientReq struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	Redirects []string `json:"redirects"`
	Grants    []string `json:"grant_types"`
	Responses []string `json:"response_types"`
}

var clientNameExp = regexp.MustCompile(`([a-zA-Z0-9\. ]+)`)
var validResponses = []string{"code", "token"}

// ClientsPost creates a new OAuth client
func (c *APICtx) ClientsPost(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	// Decode client request
	clientReq := ClientReq{}
	defer req.Body.Close()
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&clientReq); err != nil {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.DecodingFailed)
		return
	}

	// Validate name
	if !clientNameExp.MatchString(clientReq.Name) {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.OAuthInvalidClientName)
		return
	}

	// Validate request URLs
	for _, url := range clientReq.Redirects {
		if !govalidator.IsURL(url) {
			c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.OAuthInvalidRedirect)
			return
		}
	}

	// TODO: Validate response types

	// Create client instance
	client, err := c.oc.CreateClient(c.GetUserID(), clientReq.Name, clientReq.Scopes, clientReq.Redirects, clientReq.Grants, clientReq.Responses, true)
	if err != nil {
		log.Printf("oauth.ClientsPost error creating client: %s", err)
		c.WriteInternalError(rw)
		return
	}

	c.WriteJSON(rw, client)
}

// AuthorizeRequestGet External OAuth authorization endpoint
func (c *APICtx) AuthorizeRequestGet(rw web.ResponseWriter, req *web.Request) {

	// Process authorization request
	ar, err := c.oc.OAuth2.NewAuthorizeRequest(c.fositeContext, req.Request)
	if err != nil {
		log.Printf("Oauth AuthorizeResponseGet error: %s", err)
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
		c.BindRedirect(c.oc.config.AuthorizeRedirect, rw, req)
		c.DoRedirect("/login", rw, req)
		return
	}

	// Redirect to pending auth page if logged in
	c.DoRedirect(c.oc.config.AuthorizeRedirect, rw, req)

}

type AuthorizationRequest struct {
	State       string   `json:"state"`
	Name        string   `json:"name"`
	RedirectURI string   `json:"redirect_uri"`
	Scopes      []string `json:"scopes"`
}

// AuthorizePendingGet Fetch pending authorizations for a user
func (c *APICtx) AuthorizePendingGet(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	// Fetch OAuth Authorization Request from session
	if c.GetSession().Values["oauth"] == nil {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.OAuthNoAuthorizePending)
		return
	}
	ar := c.GetSession().Values["oauth"].(fosite.AuthorizeRequest)

	// Client is an interface so cannot be parsed to or from json
	ar.Client = nil

	// Map to safe API struct
	resp := AuthorizationRequest{
		State: ar.State,
		//Name:        ar.GetClient().(Client).GetName(),
		RedirectURI: ar.RedirectURI.String(),
		Scopes:      []string(ar.GetRequestedScopes()),
	}

	// Write back to user
	c.WriteJSON(rw, &resp)
}

// AuthorizeConfirm authorization confirmation object
type AuthorizeConfirm struct {
	Accept        bool     `json:"accept"`
	State         string   `json:"state"`
	GrantedScopes []string `json:"granted_scopes"`
}

// AuthorizeConfirmPost Confirm authorization of a token
// This finalises and stores the authentication, and redirects back to the calling service
// TODO: this endpoint /really/ needs CSRF / CORS protection
func (c *APICtx) AuthorizeConfirmPost(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	// Fetch authorization request from session
	if c.GetSession().Values["oauth"] == nil {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.OAuthNoAuthorizePending)
		return
	}

	authorizeConfirm := AuthorizeConfirm{}
	defer req.Body.Close()
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&authorizeConfirm); err != nil {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.DecodingFailed)
		return
	}

	if len(authorizeConfirm.GrantedScopes) == 0 {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.OAuthNoGrantedScopes)
		return
	}

	authorizeRequest := c.GetSession().Values["oauth"].(fosite.AuthorizeRequest)

	if !authorizeConfirm.Accept {
		session := c.GetSession()
		session.Values["oauth"] = nil
		session.Save(req.Request, rw)
		return
	}

	oauthSession := Session{
		UserID: c.GetUserID(),
	}

	oauthSession.AccessExpiry = time.Now().Add(time.Hour * 1)
	oauthSession.IDExpiry = time.Now().Add(time.Hour * 1)
	oauthSession.AuthorizeExpiry = time.Now().Add(time.Hour * 1)
	oauthSession.RefreshExpiry = time.Now().Add(time.Hour * 24)

	log.Printf("AuthConfirm: %+v", authorizeConfirm)

	// Validate that granted scopes match those available in AuthorizeRequest
	for _, granted := range authorizeConfirm.GrantedScopes {
		if fosite.HierarchicScopeStrategy(authorizeRequest.GetRequestedScopes(), granted) {
			authorizeRequest.GrantedScopes = append(authorizeRequest.GrantedScopes, granted)
		}
	}

	authorizeRequest.HandledResponseTypes = validResponses
	log.Printf("AuthRequest: %+v", authorizeRequest)

	// Create response
	response, err := c.oc.OAuth2.NewAuthorizeResponse(c.fositeContext, &authorizeRequest, NewSessionWrap(&oauthSession))
	if err != nil {
		log.Printf("OauthAPI.AuthorizeConfirmPost error: %s", errors.Cause(err))
		c.oc.OAuth2.WriteAuthorizeError(rw, &authorizeRequest, err)
		return
	}

	log.Printf("AuthResponse: %+v", response)

	// Write output
	c.oc.OAuth2.WriteAuthorizeResponse(rw, &authorizeRequest, response)
}

// IntrospectPost Token Introspection endpoint
func (c *APICtx) IntrospectPost(rw web.ResponseWriter, req *web.Request) {

	ctx := fosite.NewContext()
	session := Session{}

	response, err := c.oc.OAuth2.NewIntrospectionRequest(ctx, req.Request, NewSessionWrap(&session))
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
		log.Printf("OauthAPI.AccessTokenInfoGet GetAccessTokenInfo error: %s", err)
		c.WriteInternalError(rw)
		return
	}
	if token == nil {
		c.WriteAPIResultWithCode(rw, http.StatusBadRequest, api.OAuthNoTokenFound)
		return
	}

	c.WriteJSON(rw, token)
}

// TokenPost Uses an authorization to fetch an access token
func (c *APICtx) TokenPost(rw web.ResponseWriter, req *web.Request) {
	ctx := fosite.NewContext()

	// Create session
	session := Session{
		AccessExpiry:    time.Now().Add(time.Hour * 1),
		IDExpiry:        time.Now().Add(time.Hour * 2),
		RefreshExpiry:   time.Now().Add(time.Hour * 3),
		AuthorizeExpiry: time.Now().Add(time.Hour * 4),
	}

	// TODO: How on earth do I pull a user ID out of this?
	// Should be associated with an oauth request type, but I don't have access to it here.

	// Create access request
	ar, err := c.oc.OAuth2.NewAccessRequest(ctx, req.Request, NewSessionWrap(&session))
	if err != nil {
		log.Printf("OauthAPI.TokenPost NewAccessRequest error: %s", err)
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
	// I think client_credentials should be limited to introspection only (no app level permissions)
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	// Build response
	response, err := c.oc.OAuth2.NewAccessResponse(ctx, ar)
	if err != nil {
		log.Printf("OauthAPI.TokenPost NewAccessResponse error: %s", err)
		c.oc.OAuth2.WriteAccessError(rw, ar, err)
		return
	}

	// Write response to client
	c.oc.OAuth2.WriteAccessResponse(rw, ar, response)
}

// SessionsInfoGet Lists authorized sessions for a user
func (c *APICtx) SessionsInfoGet(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		c.WriteUnauthorized(rw)
		return
	}

	sessions, err := c.oc.GetUserSessions(c.GetUserID())
	if err != nil {
		log.Printf("OauthAPI.SessionsInfoGet GetUserSessions error: %s", err)
		c.WriteInternalError(rw)
		return
	}

	c.WriteJSON(rw, sessions)
}

// TestGet test endpoint
func (c *APICtx) TestGet(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusOK)
}
