package core

import (
	"net/http"
	"log"
)

import (
	"github.com/gocraft/web"
	"github.com/asaskevich/govalidator"
)

// Auth status for module pre/post auth handlers
type AuthStatus string

const (
	// Module authentication OK
	AuthOk      AuthStatus = "ok"
	// Module authentication pending
	// The module returning this must redirect the requester and complete authentication
	AuthPending AuthStatus = "pending"
	// Module authentication failed
	// The module returning this must return an to the requester
	AuthFailed  AuthStatus = "failed"
)

type AuthResult map[string]AuthStatus

func (ar *AuthResult) containsResult(status AuthStatus) bool {
	for _, v := range(ar) {
		if v == status {
			return true
		}
	}
	return false
}

func (ar *AuthResult) Failed() bool {
	return ar.containsResult(AuthFailed)
}

func (ar *AuthResult) Pending() bool {
	return !ar.containsResult(AuthFailed) && ar.containsResult(AuthPending)
}

func (ar *AuthResult) Success() bool {
	return !ar.containsResult(AuthFailed) && !ar.containsResult(AuthPending)
}

type Module interface {
	// Pre-auth handlers for pre user rate limiting / IP blocking etc.
	PreAuth(rw web.ResponseWriter, req *web.Request) (bool, error)
	// Post-auth handlers for further modules, ie. U2F, logging.
	// These handlers can intercept and continue the login flow later
	PostAuth(userid string, rw web.ResponseWriter, req *web.Request) (AuthStatus, error)
}

// Basic login control interface
type LoginControl interface {
	// Delegated login call, this must return true/false for password failure/success 
	// as well as the user object if found
	Login(email string, password string) (bool, *User, error)
}

type User interface {
	GetId() string
}

const (
	StatusOk 	string = "ok"
	StatusError string = "error"
)

type ModuleResponse struct {
	// Response Status
	status string
	// Message to user
	message string
	// URL to continue if required
	url string
}

type ModuleManager struct {
	// Base login control
	lc *LoginControl
	// Modules bound into the manager
	modules map[string]Module
}

// Create a new module manager instance
func NewModuleManager(lc* LoginControl) *ModuleManager {
	modules := make(map[string]Module)
	return &ModuleManager{lc, modules}
}

func (m *ModuleManager) BindModule(name string, mod Module) {
	m.modules[name] = mod
}

func (m *ModuleManager) Login(rw web.ResponseWriter, req *web.Request) {
	// Fetch parameters
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	password := req.FormValue("password")
	if password == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Run pre-login hooks
	for name, module := range m.modules {
		ok, err := module.PreAuth(rw, req)
		if err != nil {
			rw.WriteHeader(http.StatusInternalError)
			log.Printf("ModuleManager module: %s error: %s\n", name, err);
			return
		}
		if !ok {
			rw.WriteHeader(http.StatusUnauthorized)
			log.Printf("ModuleManager pre-auth blocked by module %s\n", name);
			return
		}
	}

	// Attempt basic (password) login
	ok, u, e := m.lc.Login(email, password)

	// Handle login module errors
	if e != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		log.Printf("ModuleManager: login error %s\n", e)
		return
	}

	// Handle immediate login failure
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		log.Println("ModuleManager: login failed, invalid password\n")
		return
	}

	// Run post-login hooks
	postAuth := make(AuthResult)
	for name, module := range m.modules {
		res, err := module.PostAuth(rw, req)
		if err != nil {
			rw.WriteHeader(http.StatusInternalError)
			log.Printf("ModuleManager post-auth module: %s error: %s\n", name, err);
			return
		}
		postAuth[name] = res;
	}

	// Check for failures
	if postAuth.Failed() {
		rw.WriteHeader(http.StatusUnauthorized)
		log.Printf("ModuleManager: post-auth blocked\n")
	}

	// Check for pending components
	if postAuth.Pending() {

	}

	//
	log.Printf("ModuleManager: auth failed (unknown path)\n")
	rw.WriteHeader(http.StatusUnauthorized)
}

func (m *ModuleManager) PostLogin(rw web.ResponseWriter, req *web.Request) {
	// For each bound module
	for name, module := range m.modules {
		res, err := module.PostAuth(rw, req)
		if err != nil {
			rw.WriteHeader(http.StatusInternalError)
			log.Printf("ModuleManager post-auth module: %s error: %s\n", name, err);
			return
		}
		if res == AuthFailed {
			rw.WriteHeader(http.StatusUnauthorized)
			log.Printf("ModuleManager post-auth blocked by module %s\n", name);
			return;
		}
		if res == AuthPending {
			//TODO: cache auth state for future completion
			return;
		}
	}

	log.Printf("Login: Login failed\n")
	rw.WriteHeader(http.StatusUnauthorized)
}

type FidoModule struct {
	authUrl string
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

