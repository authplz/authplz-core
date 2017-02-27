package user;

import (
    "time"
    "errors"
)

// Defines the User object interface required by this module
type User interface {
    GetExtId() string
    GetEmail() string

    GetPassword() string
    SetPassword(pass string)
    GetPasswordChanged() time.Time

    IsActivated() bool
    SetActivated(activated bool)

    IsEnabled() bool
    SetEnabled(locked bool)

    GetLoginRetries() uint
    SetLoginRetries(retries uint)

    GetLastLogin() time.Time
    SetLastLogin(t time.Time)

    IsLocked() bool
    SetLocked(locked bool)
}

// Defines the required store interfaces for the user module
type UserStoreInterface interface {
    AddUser(email string, pass string) (interface{}, error)
    GetUserByExtId(userid string) (interface{}, error)
    GetUserByEmail(email string) (interface{}, error)
    UpdateUser(user interface{}) (interface{}, error)
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
