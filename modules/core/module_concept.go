package core

import (
	"log"
	"net/http"
)

import (
	"github.com/asaskevich/govalidator"
	"github.com/gocraft/web"
)

// Auth status for module pre/post auth handlers
type AuthStatus string

const (
	// Module authentication OK
	AuthOk AuthStatus = "ok"
	// Module authentication pending
	// The module returning this must redirect the requester and complete authentication
	AuthPending AuthStatus = "pending"
	// Module authentication failed
	// The module returning this must return an to the requester
	AuthFailed AuthStatus = "failed"
)

type Module interface {
	// Pre-auth handlers for pre user rate limiting / IP blocking etc.
	// These are run prior to user identification
	PreAuth(rw web.ResponseWriter, req *web.Request) (bool, error)
	// Post-auth handlers for further modules, ie. mailing, analytics.
	// These are run after user password has been accepted
	PostAuth(userid string, rw web.ResponseWriter, req *web.Request) (bool, error)
}

type PreAuthHandler interface {
	// Pre-auth handlers for pre user rate limiting / IP blocking etc.
	PreAuth(rw web.ResponseWriter, req *web.Request) (bool, error)
}

type PostAuthHandler interface {
	// Post-auth handlers for further modules, ie. U2F, logging.
	PostAuth(userid string, rw web.ResponseWriter, req *web.Request) (bool, error)
}

// Basic login control interface
type LoginControl interface {
	// Delegated login call, this must return true/false for password failure/success
	// as well as the user object if found
	Login(email string, password string) (bool, UserInterface, error)
}

type SecondFactor interface {
	CanAuthenticate(userid string) (bool, error)
}

const (
	StatusOk    string = "ok"
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
	lc LoginControl
	// Modules bound into the manager
	modules map[string]Module
}

// Create a new module manager instance
func NewModuleManager(lc LoginControl) *ModuleManager {
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
			rw.WriteHeader(http.StatusInternalServerError)
			log.Printf("ModuleManager module: %s error: %s\n", name, err)
			return
		}
		if !ok {
			rw.WriteHeader(http.StatusUnauthorized)
			log.Printf("ModuleManager pre-auth blocked by module %s\n", name)
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

	// Run post-auth hooks
	for name, module := range m.modules {
		res, err := module.PostAuth(u.GetExtId(), rw, req)
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			log.Printf("ModuleManager post-auth module: %s error: %s\n", name, err)
			return
		}
		if !res {
			rw.WriteHeader(http.StatusUnauthorized)
			log.Printf("ModuleManager post-auth blocked by module %s\n", name)
			return
		}
	}

	// TODO: enact login
	log.Printf("ModuleManager: auth failed (unknown path)\n")
	rw.WriteHeader(http.StatusUnauthorized)
}
