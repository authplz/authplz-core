package core

import (
	"log"
)

import (
	"github.com/ryankurte/authplz/api"
)

// Controller core module instance storage
// The core module implements basic login/logout methods and allows binding of modules
// To interrupt/assist/log the execution of each
type Controller struct {
	// Token controller for parsing of tokens
	tokenControl TokenValidator

	// User controller interface for basic user logins
	userControl LoginProvider

	// Token handler implementations
	// This allows token handlers to be bound on a per-module basis using the actions
	// defined in api.TokenAction. Note that there must not be overlaps in bindings
	// TODO: this should probably be implemented as a bind function to panic if overlap is attempted
	tokenHandlers map[api.TokenAction]TokenHandler

	// 2nd Factor Authentication implementations
	secondFactorHandlers map[string]SecondFactorProvider

	// Event handler implementations
	eventHandlers map[string]EventHandler

	// Login handler implementations
	preLogin         map[string]PreLoginHook
	postLoginSuccess map[string]PostLoginSuccessHook
	postLoginFailure map[string]PostLoginFailureHook
}

// NewController Create a new core module instance
func NewController(tokenValidator TokenValidator, loginProvider LoginProvider) *Controller {
	return &Controller{
		tokenControl:         tokenValidator,
		userControl:          loginProvider,
		tokenHandlers:        make(map[api.TokenAction]TokenHandler),
		secondFactorHandlers: make(map[string]SecondFactorProvider),

		preLogin:         make(map[string]PreLoginHook),
		postLoginSuccess: make(map[string]PostLoginSuccessHook),
		postLoginFailure: make(map[string]PostLoginFailureHook),
		eventHandlers:    make(map[string]EventHandler),
	}
}

// BindActionHandler Binds a token action handler instance to the core module
// Token actions are validated and executed following successful login
func (coreModule *Controller) BindActionHandler(action api.TokenAction, thi TokenHandler) {
	// TODO: check if exists before attaching and throw an error
	coreModule.tokenHandlers[action] = thi
}

// BindSecondFactor Binds a 2fa handler instance into the core module
// 2fa handlers must return whether they are available for a given user.
// If any 2fa module returns true, login will be halted, the user alerted (with available options),
// and a 2fa-pending session variable set in the global context for a 2fa implementation to
// pick up
func (coreModule *Controller) BindSecondFactor(name string, sfi SecondFactorProvider) {
	// TODO: check if exists before attaching and throw an error
	coreModule.secondFactorHandlers[name] = sfi
}

// BindEventHandler Binds an event handler interface into the core module
// Event handlers are called during a variety of evens
func (coreModule *Controller) BindEventHandler(name string, ehi EventHandler) {
	coreModule.eventHandlers[name] = ehi
}

// BindPreLogin Binds a PreLogin handler interface to the core module
// PreLogin handlers are called in the login chain to check login requirements
func (coreModule *Controller) BindPreLogin(name string, lhi PreLoginHook) {
	coreModule.preLogin[name] = lhi
}

// BindPostLoginSuccess binds a PostLoginSuccess handler interface to the core module
// This handler will be called on successful logins
func (coreModule *Controller) BindPostLoginSuccess(name string, plsi PostLoginSuccessHook) {
	coreModule.postLoginSuccess[name] = plsi
}

// BindPostLoginFailure binds a PostLoginFailure handler interface to the core module
// This handler will be called on failed logins
func (coreModule *Controller) BindPostLoginFailure(name string, plfi PostLoginFailureHook) {
	coreModule.postLoginFailure[name] = plfi
}

// BindModule Magic binding function, detects interfaces implemented by a given module
// and binds as appropriate
func (coreModule *Controller) BindModule(name string, mod interface{}) {
	if i, ok := mod.(SecondFactorProvider); ok {
		coreModule.BindSecondFactor(name, i)
	}
	if i, ok := mod.(EventHandler); ok {
		coreModule.BindEventHandler(name, i)
	}
	if i, ok := mod.(PreLoginHook); ok {
		coreModule.BindPreLogin(name, i)
	}
	if i, ok := mod.(PostLoginSuccessHook); ok {
		coreModule.BindPostLoginSuccess(name, i)
	}
	if i, ok := mod.(PostLoginFailureHook); ok {
		coreModule.BindPostLoginFailure(name, i)
	}
}

// CheckSecondFactors Determine whether a second factor is required for a user
// This returns a bool indicating whether 2fa is required, and a map of the available 2fa mechanisms
func (coreModule *Controller) CheckSecondFactors(userid string) (bool, map[string]bool) {

	availableHandlers := make(map[string]bool)
	secondFactorRequired := false

	for key, handler := range coreModule.secondFactorHandlers {
		supported := handler.IsSupported(userid)
		if supported {
			secondFactorRequired = true
		}
		availableHandlers[key] = supported
	}

	return secondFactorRequired, availableHandlers
}

// HandleToken Handles a token string for a given user
// Returns accepted bool and error in case of failure
func (coreModule *Controller) HandleToken(userid string, user interface{}, tokenString string) (bool, error) {
	action, err := coreModule.tokenControl.ValidateToken(userid, tokenString)
	if err != nil {
		log.Printf("CoreModule.Login: token validation failed %s\n", err)
		return false, nil
	}

	// Locate token handler
	tokenHandler, ok := coreModule.tokenHandlers[*action]
	if !ok {
		log.Printf("CoreModule.HandleToken: no token handler found for action %s\n", action)
		return false, err
	}

	// Execute token action
	err = tokenHandler.HandleToken(user, *action)
	if err != nil {
		log.Printf("CoreModule.HandleToken: token action %s handler error %s\n", action, err)
		return false, err
	}

	log.Printf("CoreModule.HandleToken: token action %v executed for user %s\n", *action, userid)
	return true, nil
}

// PreLogin Runs bound login handlers to accept user logins
func (coreModule *Controller) PreLogin(u interface{}) (bool, error) {
	for key, handler := range coreModule.preLogin {
		ok, err := handler.PreLogin(u)
		if err != nil {
			log.Printf("CoreModule.LoginHandlers: error in handler %s (%s)", key, err)
			return false, err
		}
		if !ok {
			log.Printf("CoreModule.LoginHandlers: login blocked by handler %s", key)
			return false, nil
		}
	}

	return true, nil
}

// PostLoginSuccess Runs bound post login success handlers
func (coreModule *Controller) PostLoginSuccess(u interface{}) error {
	for key, handler := range coreModule.postLoginSuccess {
		err := handler.PostLoginSuccess(u)
		if err != nil {
			log.Printf("CoreModule.PostLoginSuccess: error in handler %s (%s)", key, err)
			return err
		}
	}
	return nil
}

// PostLoginFailure Runs bound post login failure handlers
func (coreModule *Controller) PostLoginFailure(u interface{}) error {
	for key, handler := range coreModule.postLoginFailure {
		err := handler.PostLoginFailure(u)
		if err != nil {
			log.Printf("CoreModule.PostLoginFailure: error in handler %s (%s)", key, err)
			return err
		}
	}
	return nil
}
