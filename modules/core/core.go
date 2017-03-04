package core

import (
	"log"
)

import (
	"github.com/ryankurte/authplz/api"
)

type CoreModule struct {
	// Token controller for parsing of tokens
	tokenControl TokenControlInterface

	// User controller interface for basic user logins
	userControl UserControlInterface

	// Token handler implementations
	// This allows token handlers to be bound on a per-module basis using the actions
	// defined in api.TokenAction. Note that there must not be overlaps in bindings
	// TODO: this should probably be implemented as a bind function to panic if overlap is attempted
	tokenHandlers        map[api.TokenAction]TokenHandlerInterface
	secondFactorHandlers map[string]SecondFactorInterface
}

// Create a new core module instance
// The core module implements basic login/logout methods and allows binding of modules
// To interrupt/assist/log the execution of each
func NewCoreModule(tokenControl TokenControlInterface, userControl UserControlInterface) *CoreModule {
	return &CoreModule{
		tokenControl:         tokenControl,
		userControl:          userControl,
		tokenHandlers:        make(map[api.TokenAction]TokenHandlerInterface),
		secondFactorHandlers: make(map[string]SecondFactorInterface),
	}
}

// Bind a token action handler instance to the core module
// Token actions are validated and executed following successful login
func (coreModule *CoreModule) BindActionHandler(action api.TokenAction, thi TokenHandlerInterface) {
	// TODO: check if exists before attaching and throw an error
	coreModule.tokenHandlers[action] = thi
}

// Bind a 2fa handler instance into the core module
// 2fa handlers must return whether they are available for a given user.
// If any 2fa module returns true, login will be halted, the user alerted (with available options),
// and a 2fa-pending session variable set in the global context for a 2fa implementation to
// pick up
func (coreModule *CoreModule) BindSecondFactor(name string, sfi SecondFactorInterface) {
	// TODO: check if exists before attaching and throw an error
	coreModule.secondFactorHandlers[name] = sfi
}

// Determine whether a second factor is required for a user
// This returns a bool indicating whether 2fa is required, and a map of the available 2fa mechanisms
func (coreModule *CoreModule) CheckSecondFactors(userid string) (bool, map[string]bool) {

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

// Handle a token string for a given user
// Returns accepted bool and error in case of failure
func (coreModule *CoreModule) HandleToken(userid string, user interface{}, tokenString string) (bool, error) {
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

