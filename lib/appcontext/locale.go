package appcontext

import (
	"github.com/gocraft/web"

	"github.com/ryankurte/authplz/lib/api"
)

// GetLocaleMiddleware Middleware to grab locale query string or cookies for use in API responses
func (c *AuthPlzCtx) GetLocaleMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	queryLocale := req.URL.Query().Get("locale")
	if queryLocale != "" {
		// Update session locale
		c.locale = queryLocale
		c.session.Values["locale"] = queryLocale
		c.session.Save(req.Request, rw)
	} else {
		// Fetch and save locale to context
		sessionLocale := c.session.Values["locale"]
		if sessionLocale != nil {
			c.locale = sessionLocale.(string)
		} else {
			c.locale = api.DefaultLocale
		}
	}

	next(rw, req)
}

// GetLocale fetches the user locale from the session
func (c *AuthPlzCtx) GetLocale() string {
	if c.locale != "" {
		return c.locale
	} else {
		return api.DefaultLocale
	}
}

// GetAPILocale fetch the APIMessageContainer for a given language to provide locale specific response messages
func (c *AuthPlzCtx) GetAPILocale() *api.ApiMessageContainer {
	return api.GetAPILocale(c.GetLocale())
}
