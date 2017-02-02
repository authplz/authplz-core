package user

import "errors"

// User control errors
var (
	ErrorPasswordTooShort     = errors.New("User Controller: password does not meet complexity requirements")
	ErrorPasswordHashTooShort = errors.New("User Controller: password hash too short")
	ErrorFindingUser          = errors.New("User Controller: error checking for user account")
	ErrorDuplicateAccount     = errors.New("User Controller: user account with email exists")
	ErrorCreatingUser         = errors.New("User Controller: error creating user")
	ErrorUserNotFound         = errors.New("User Controller: user not found")
	ErrorPasswordMismatch     = errors.New("User Controller: password mismatch")
	ErrorUpdatingUser         = errors.New("User Controller: error updating user")
	ErrorAddingToken          = errors.New("User Controller: error adding token")
	ErrorUpdatingToken        = errors.New("User Controller: error updating token")
)
