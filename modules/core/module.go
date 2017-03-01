package core

import(
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
    tokenHandlers map[api.TokenAction]TokenHandlerInterface
}

// Create a new core module instance
func NewCoreModule(tokenControl TokenControlInterface, userControl UserControlInterface) *CoreModule {
    return &CoreModule{
        tokenControl: tokenControl,
        userControl: userControl,
        tokenHandlers: make(map[api.TokenAction]TokenHandlerInterface),
    }
}

// Bind an action handler instance to the core module
func (coreModule *CoreModule) BindActionHandler(action api.TokenAction, thi TokenHandlerInterface) {
    // TODO: check if exists before attaching and throw an error
    coreModule.tokenHandlers[action] = thi
}
