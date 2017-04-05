package core

import (
	"github.com/ryankurte/authplz/lib/api"
)

// LoginProvider Interface for a user control module
type LoginProvider interface {
	// Login method, returns boolean result, user interface for further use, error in case of failure
	Login(email string, password string) (bool, interface{}, error)
	GetUserByEmail(email string) (interface{}, error)
}

// TokenValidator Interface for token (creation and?) validation
type TokenValidator interface {
	ValidateToken(userid string, tokenString string) (*api.TokenAction, error)
}

// SecondFactorProvider for 2 factor authentication modules
// These modules must inform the login handler as to whether
// further authentication is supported
type SecondFactorProvider interface {
	// Check whether a user can use this 2fa module
	// This depends on what second factors are registered
	IsSupported(userid string) bool
}

// TokenHandler for token handler modules
// These modules accept a token action and user id to execute a task
// For example, the user module accepts 'activate' and 'unlock' actions
type TokenHandler interface {
	HandleToken(userid string, tokenAction api.TokenAction) error
}

// Core Event Hook Interfaces

// PreLoginHook PreLogin hooks may allow or deny login
type PreLoginHook interface {
	PreLogin(u interface{}) (bool, error)
}

// PostLoginSuccessHook Post login success hooks called on login success
type PostLoginSuccessHook interface {
	PostLoginSuccess(u interface{}) error
}

// PostLoginFailureHook Post login failure hooks called on login failure
type PostLoginFailureHook interface {
	PostLoginFailure(u interface{}) error
}

// EventHandler Interface for event handler modules
// These modules are bound into the event manager to provide asynchronous services
// based on system events.
// For example, the mailer module accepts a variety of user events and sends mail in response.
type EventHandler interface {
	HandleEvent(userid string, u interface{}) error
}

// UserInterface Interface for user instances
type UserInterface interface {
	GetExtID() string
	GetEmail() string
}
