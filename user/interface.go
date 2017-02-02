package user;

import (
    "time"
)

// Defines the User object interface required by this module
type User interface {
    GetId() string
    SetPassword(pass string)
    SetPasswordUpdated(t time.Time)
}

// Defines the required store interfaces for the user module
type UserStoreInterface interface {
    AddUser(email string, pass string) (user User, err error)
    GetUserByExtId(userid string) (user User, err error)
    GetUserByEmail(email string) (user User, err error)
    UpdateUser(user interface{}) (User, error)
}

// Login status return objects
type LoginStatus struct {
    Code    uint64
    Message string
}

// User controller status enumerations
const (
    LoginCodeSuccess     = iota // Login complete
    LoginCodeFailure     = iota // Login failed
    LoginCodePartial     = iota // Further credentials required
    LoginCodeLocked      = iota // Account locked
    LoginCodeUnactivated = iota // Account not yet activated
    LoginCodeDisabled    = iota // Account disabled
)

// Login return object instances
var LoginSuccess = LoginStatus{LoginCodeSuccess, "Login successful"}
var LoginFailure = LoginStatus{LoginCodeFailure, "Invalid username or password"}
var LoginRequired = LoginStatus{LoginCodeFailure, "Login required"}
var LoginPartial = LoginStatus{LoginCodeFailure, "Second factor required"}
var LoginLocked = LoginStatus{LoginCodeLocked, "User account locked"}
var LoginUnactivated = LoginStatus{LoginCodeUnactivated, "User account not activated"}
var LoginDisabled = LoginStatus{LoginCodeDisabled, "User account disabled"}

var loginError = errors.New("internal server error")
