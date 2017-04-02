// Defines API messages

package api

import (
	"log"
)

// API result types
const ResultOk string = "ok"
const ResultError string = "error"

// Common API response object
type ApiResponse struct {
	// Either "ok" indicating success or "error" indicating failure
	Result string `json:"result"`
	// Message corresponding to response status
	Message string `json:"message"`
}

// API status message container
// Represents all available API instances
type ApiMessageContainer struct {
	CreateUserSuccess        string
	PasswordComplexityTooLow string
	LoginSuccessful          string
	LogoutSuccessful         string
	ActivationSuccessful     string
	UnlockSuccessful         string
	PasswordUpdated          string
	AlreadyAuthenticated     string
	Unauthorized             string
	InvalidToken             string
	InternalError            string
	SecondFactorRequired     string
	U2FRegistrationFailed    string
	U2FRegistrationComplete  string
	NoU2FPending             string
	NoU2FTokenFound          string
	TokenNameRequired        string
	NoOAuthPending           string
	NoOAuthTokenFound        string
	FormParsingError         string
	DuplicateUserAccount     string
}

// Create API message structure for English responses
// TODO: these structs should be loaded from the template directory
var ApiMessageEn = ApiMessageContainer{
	CreateUserSuccess:        "Created user account, check your emails for an activation token",
	PasswordComplexityTooLow: "Password does not meet complexity requirements",
	LoginSuccessful:          "Login successful",
	LogoutSuccessful:         "Logout successful",
	ActivationSuccessful:     "Account activation successful",
	UnlockSuccessful:         "Account unlock successful",
	PasswordUpdated:          "Password Updated",
	AlreadyAuthenticated:     "Already logged in, please log out to change accounts",
	Unauthorized:             "You must be logged in to view this page",
	InvalidToken:             "Invalid token",
	InternalError:            "Internal server error",
	U2FRegistrationFailed:    "U2F Registration failed",
	SecondFactorRequired:     "U2F Authentication required",
	U2FRegistrationComplete:  "U2F Registration complete",
	NoU2FPending:             "U2F no authentication pending",
	NoU2FTokenFound:          "U2F matching u2f token found",
	TokenNameRequired:        "U2F token name required",
	NoOAuthPending:           "No OAuth authorization pending",
	NoOAuthTokenFound:        "No OAuth Token Found",
	FormParsingError:         "Error parsing submitted form",
	DuplicateUserAccount:     "A user account with that username or email address already exists",
}

// Default locale for external use
var DefaultLocale string = "en"

// Fetch the APIMessageContainer for a given language to provide locale specific response messages
func GetApiLocale(lang string) *ApiMessageContainer {
	switch lang {
	case "en":
		return &ApiMessageEn
	default:
		log.Printf("API message unhandled request for locale: %s\n", lang)
		return &ApiMessageEn
	}
}

// API Response instances
// TODO: deprecate these
var ApiResponseLoginSuccess = ApiResponse{ResultOk, GetApiLocale(DefaultLocale).LoginSuccessful}
var ApiResponseLogoutSuccess = ApiResponse{ResultOk, GetApiLocale(DefaultLocale).LogoutSuccessful}
var ApiResponseActivationSuccessful = ApiResponse{ResultOk, GetApiLocale(DefaultLocale).ActivationSuccessful}
var ApiResponseUnlockSuccessful = ApiResponse{ResultOk, GetApiLocale(DefaultLocale).UnlockSuccessful}

var ApiResponseUnauthorized = ApiResponse{ResultError, GetApiLocale(DefaultLocale).Unauthorized}
var ApiResponseInvalidToken = ApiResponse{ResultError, GetApiLocale(DefaultLocale).InvalidToken}
var ApiResponseInternalError = ApiResponse{ResultError, GetApiLocale(DefaultLocale).InternalError}
