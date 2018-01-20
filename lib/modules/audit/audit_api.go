package audit

import (
	"log"
	"net/http"
)

import (
	"github.com/authplz/authplz-core/lib/appcontext"
	"github.com/gocraft/web"
)

// APICtx API context instance
type APICtx struct {
	// Base context required by router
	*appcontext.AuthPlzCtx
	// User module instance
	ac *Controller
}

// BindAuditContext Helper middleware to bind module to API context
func BindAuditContext(ac *Controller) func(ctx *APICtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *APICtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.ac = ac
		next(rw, req)
	}
}

// BindAPI binds the AuditController API to a provided router
func (ac *Controller) BindAPI(router *web.Router) {
	// Create router for user modules
	auditRouter := router.Subrouter(APICtx{}, "/api/audit")

	// Attach module context
	auditRouter.Middleware(BindAuditContext(ac))

	// Bind endpoints
	auditRouter.Get("/", (*APICtx).GetEvents)
}

// GetEvents endpoint fetches a list of audit events for a given user
func (c *APICtx) GetEvents(rw web.ResponseWriter, req *web.Request) {
	// Check user is logged in
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	events, err := c.ac.ListEvents(c.GetUserID())
	if err != nil {
		log.Printf("AuditApiCtx.GetEvents: error listing events (%s)", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	c.WriteJSON(rw, events)
}
