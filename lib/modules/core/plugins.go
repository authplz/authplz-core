/*
 * Core module controller plugin management
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package core

import (
	"github.com/authplz/authplz-core/lib/api"
)

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
