package audit

import (
    "log"
    "net/http"
)

import (
    "github.com/gocraft/web"
    "github.com/ryankurte/authplz/appcontext"
)

// API context instance
type AuditApiCtx struct {
    // Base context required by router
    *appcontext.AuthPlzCtx
    // User module instance
    ac *AuditController
}

// Helper middleware to bind module to API context
func BindAuditContext(ac *AuditController) func(ctx *AuditApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
    return func(ctx *AuditApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
        ctx.ac = ac
        next(rw, req)
    }
}

func (ac *AuditController) BindAPI(router *web.Router) {
    // Create router for user modules
    auditRouter := router.Subrouter(AuditApiCtx{}, "/api/audit")

    // Attach module context
    auditRouter.Middleware(BindAuditContext(ac))

    // Bind endpoints
    auditRouter.Get("/", (*AuditApiCtx).GetEvents)
}

// Fetch a list of audit events for a given user
func (c *AuditApiCtx) GetEvents(rw web.ResponseWriter, req *web.Request) {
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

    c.WriteJson(rw, events)
}

