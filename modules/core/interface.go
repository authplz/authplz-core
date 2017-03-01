package core

import (
    "github.com/ryankurte/authplz/api"
)

// Interface for a user control module
type UserControlInterface interface {
    // Login method, returns api.LoginStatus result, user interface for further use, error in case of failure
    Login(email, password string) (*api.LoginStatus, interface{}, error)
}

// Interface for token validation
type TokenControlInterface interface {
    ValidateToken(userid string, tokenString string) (*api.TokenAction, error)
}

// Interface for token handler modules
type TokenHandlerInterface interface {
    HandleToken(u interface{}, tokenAction api.TokenAction) error
}



// Interface for user instances
type UserInterface interface {
    GetExtId() string
    GetEmail() string
}
