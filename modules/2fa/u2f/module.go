package u2f

import (
	"log"
)

import (
	"github.com/gocraft/web"
)

type U2FModule struct {
	url      string
	u2fStore U2FStoreInterface
}

func NewU2FModule(url string, u2fStore U2FStoreInterface) *U2FModule {
	return &U2FModule{
		url:      url,
		u2fStore: u2fStore,
	}
}

// Helper middleware to bind module to API context
func BindU2FContext(u2FModule *U2FModule) func(ctx *U2FApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *U2FApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.um = u2FModule
		next(rw, req)
	}
}

// Bind the API for the coreModule to the provided router
func (u2FModule *U2FModule) BindAPI(router *web.Router) {
	// Create router for user modules
	u2frouter := router.Subrouter(U2FApiCtx{}, "/api/u2f")

	// Attach module context
	u2frouter.Middleware(BindU2FContext(u2FModule))

	// Bind endpoints
	u2frouter.Get("/enrol", 		(*U2FApiCtx).U2FEnrolGet)
	u2frouter.Post("/enrol", 		(*U2FApiCtx).U2FEnrolPost)
	u2frouter.Get("/authenticate",  (*U2FApiCtx).U2FAuthenticateGet)
	u2frouter.Post("/authenticate", (*U2FApiCtx).U2FAuthenticatePost)
	u2frouter.Get("/tokens", 		(*U2FApiCtx).U2FTokensGet)
}

func (u2FModule *U2FModule) IsSupported(userid string) bool {
	tokens, err := u2FModule.u2fStore.GetFidoTokens(userid)
	if err != nil {
		log.Printf("U2FModule.IsSupported error fetching fido tokens for user %s (%s)", userid, tokens)
		return false
	}
	if len(tokens) == 0 {
		return false
	}
	return true
}