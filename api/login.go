// Defines messages and types for login implementations

package api

import (
    "errors"
)

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
var LoginSuccess        = &LoginStatus{LoginCodeSuccess, "Login successful"}
var LoginFailure        = &LoginStatus{LoginCodeFailure, "Invalid username or password"}
var LoginRequired       = &LoginStatus{LoginCodeFailure, "Login required"}
var LoginPartial        = &LoginStatus{LoginCodeFailure, "Second factor required"}
var LoginLocked         = &LoginStatus{LoginCodeLocked, "User account locked"}
var LoginUnactivated    = &LoginStatus{LoginCodeUnactivated, "User account not activated"}
var LoginDisabled       = &LoginStatus{LoginCodeDisabled, "User account disabled"}

var LoginError = errors.New("internal server error")
