package u2f

import "fmt"
import "log"
import "time"
import "net/http"
import "encoding/json"

import "github.com/gocraft/web"
import "github.com/ryankurte/go-u2f"

import "github.com/ryankurte/authplz/datastore"
import "github.com/ryankurte/authplz/api"

type U2FControl struct {
}

type U2FCtx interface {
}

func NewU2FModule() *U2FControl {

}

func (u *U2FControl) Bind(router *web.Router) {
	// Bind U2F control instance endpoints
	router.Get("/u2f/enrol", (*U2FCtx).U2FEnrolGet)
	router.Post("/u2f/enrol", (*U2FCtx).U2FEnrolPost)
	router.Get("/u2f/authenticate", (*U2FCtx).U2FAuthenticateGet)
	router.Post("/u2f/authenticate", (*U2FCtx).U2FAuthenticatePost)
	router.Get("/u2f/tokens", (*U2FCtx).U2FTokensGet)
}

type FidoModule struct {
	authUrl     string
	registerUrl string
}

func (f *FidoModule) PreAuth(rw web.ResponseWriter, req *web.Request) (bool, error) {
	// Stub implementation (not required)
	return true, nil
}

func (f *FidoModule) PostAuth(userid string, rw web.ResponseWriter, req *web.Request) (LoginStatus, error) {
	// If the user has tokens attached, redirect to u2f endpoint

	return AuthPending

	// If the user has no tokens, return ok
	return AuthOk
}

func (f *FidoModule) U2FAuthenticateGet(rw web.ResponseWriter, req *web.Request) {
	// Return challenges to user
}

func (f *FidoModule) U2FAuthenticatePost(rw web.ResponseWriter, req *web.Request) {
	// Check submitted response

	// Fail login if invalid

	// Continue login if valid
}
