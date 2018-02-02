/*
 * Core module controller
 * The core module exposes the base login/logout/reset/action APIs and calls bound handlers to execute each action.
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package core

import (
	"github.com/authplz/authplz-core/lib/api"
	"github.com/authplz/authplz-core/lib/events"
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

	// Event emitter for core user states
	emitter events.Emitter
}

// NewController Create a new core module instance
func NewController(tokenValidator TokenValidator, loginProvider LoginProvider, emitter events.Emitter) *Controller {
	return &Controller{
		tokenControl:         tokenValidator,
		userControl:          loginProvider,
		tokenHandlers:        make(map[api.TokenAction]TokenHandler),
		secondFactorHandlers: make(map[string]SecondFactorProvider),

		preLogin:         make(map[string]PreLoginHook),
		postLoginSuccess: make(map[string]PostLoginSuccessHook),
		postLoginFailure: make(map[string]PostLoginFailureHook),
		eventHandlers:    make(map[string]EventHandler),
		emitter:          emitter,
	}
}
