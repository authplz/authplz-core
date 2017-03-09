package oauth

import (
	"log"
	"net/http"
)

import (
	"github.com/RangelReale/osin"
	"github.com/gocraft/web"
	"github.com/ryankurte/authplz/appcontext"
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
	router.Get("/info", (*APICtx).InfoGet)
	router.Get("/test", (*APICtx).TestGet)

	// Return router for external use
	return router
}

// AuthorizeRequestGet External OAuth authorization endpoint
func (c *APICtx) AuthorizeRequestGet(rw web.ResponseWriter, req *web.Request) {

	resp := c.oc.Server.NewResponse()
	defer resp.Close()

	// Process authorization request
	ar := c.oc.Server.HandleAuthorizeRequest(resp, req.Request)
	if ar == nil {
		// Handle request errors
		if resp.IsError && resp.InternalError != nil {
			log.Printf("Oauth error: %s\n", resp.InternalError)
		}
		// Write output
		osin.OutputJSON(resp, rw, req.Request)
		return
	}

	// Add user data for later use
	ar.UserData = struct {
		Login string
	}{
		Login: "test",
	}

	// Cache authorization request
	c.GetSession().Values["oauth"] = ar
	c.GetSession().Save(req.Request, rw)

	// Check user is logged in
	if c.GetUserID() == "" {
		// TODO: redirect to login page with redirect to authorization page
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// TODO: Check if app is already authorized

	// TODO: redirect to authorization page
	rw.WriteHeader(http.StatusAccepted)
}

// AuthorizePendingGet Fetch pending authorizations
func (c *APICtx) AuthorizePendingGet(rw web.ResponseWriter, req *web.Request) {
	if c.GetSession().Values["oauth"] == nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	ar := c.GetSession().Values["oauth"].(osin.AuthorizeRequest)

	authData := struct {
		ClientID string
		Scope    string
	}{
		ar.Client.GetId(),
		ar.Scope,
	}

	c.WriteJson(rw, authData)
}

// AuthorizeConfirmPost Confirm authorization of a token
// This finalises and stores the authentication, and redirects back to the calling service
// TODO: this endpoint /really/ needs CSRF / CORS protection
func (c *APICtx) AuthorizeConfirmPost(rw web.ResponseWriter, req *web.Request) {
	resp := c.oc.Server.NewResponse()
	defer resp.Close()

	// Fetch authorization request
	if c.GetSession().Values["oauth"] == nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	ar := c.GetSession().Values["oauth"].(osin.AuthorizeRequest)

	// Validate authorization

	ar.Authorized = true
	c.oc.Server.FinishAuthorizeRequest(resp, req.Request, &ar)

	// Handle request errors
	if resp.IsError && resp.InternalError != nil {
		log.Printf("ERROR: %s\n", resp.InternalError)
	}

	// Write output
	osin.OutputJSON(resp, rw, req.Request)
}

// TokenPost Generate access token endpoint
func (c *APICtx) TokenPost(rw web.ResponseWriter, req *web.Request) {
	resp := c.oc.Server.NewResponse()
	defer resp.Close()

	if ar := c.oc.Server.HandleAccessRequest(resp, req.Request); ar != nil {

		// Fetch OauthClient instance to determine scope
		client := ar.Client.(OauthClient)
		log.Printf("%+v\n", client)

		// Force generation of a refresh token
		ar.GenerateRefresh = true

		// Attach scope from client
		ar.Scope = client.Scope

		switch ar.Type {
		case osin.CLIENT_CREDENTIALS:
			ar.Authorized = true
		case osin.AUTHORIZATION_CODE:
			ar.Authorized = true
		case osin.REFRESH_TOKEN:
			ar.Authorized = true
		}

		c.oc.Server.FinishAccessRequest(resp, req.Request, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		log.Printf("OAuth error: %s\n", resp.InternalError)
	}
	if !resp.IsError {
		resp.Output["custom_parameter"] = 19923
	}
	osin.OutputJSON(resp, rw, req.Request)
}

// InfoGet token information endpoint
func (c *APICtx) InfoGet(rw web.ResponseWriter, req *web.Request) {
	resp := c.oc.Server.NewResponse()
	defer resp.Close()

	if ir := c.oc.Server.HandleInfoRequest(resp, req.Request); ir != nil {

		// Cast back to OauthClient type
		_ = ir.AccessData.Client.(OauthClient)

		c.oc.Server.FinishInfoRequest(resp, req.Request, ir)
	}
	osin.OutputJSON(resp, rw, req.Request)
}

// TestGet test endpoint
func (c *APICtx) TestGet(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusOK)
}
