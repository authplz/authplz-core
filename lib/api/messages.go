// Defines API messages

package api

import ()

// Response Common API response object
type Response struct {
	// Response code
	Code string `json:"code"`
}

// API Response Messages for frontend / internationalisation parsing
const (
	// General messages
	NotImplemented     = "NotImplemented"
	InternalError      = "InternalError"
	FormParsingError   = "FormParsingError"
	DecodingFailed     = "DecodingFailed"
	ActionMissing      = "ActionMissing"
	IncorrectArguments = "IncorrectArguments"

	// User input messages
	InvalidEmail             = "InvalidEmail"
	InvalidUsername          = "InvalidUsername"
	MissingPassword          = "MissingPassword"
	PasswordComplexityTooLow = "PasswordComplexityTooLow"
	DuplicateUserAccount     = "DuplicateUserAccount"
	CreateUserSuccess        = "CreateUserSuccess"

	// Status messages
	LoginSuccessful      = "LoginSuccessful"
	LogoutSuccessful     = "LogoutSuccessful"
	ActivationSuccessful = "ActivationSuccessful"
	AccountLocked        = "AccountLocked"
	UnlockSuccessful     = "UnlockSuccessful"
	PasswordUpdated      = "PasswordUpdated"
	AlreadyAuthenticated = "AlreadyAuthenticated"
	Unauthorized         = "Unauthorized"
	InvalidToken         = "InvalidToken"

	// Second factor messages
	SecondFactorRequired         = "SecondFactorRequired"
	SecondFactorNoRequestSession = "SecondFactorNoSession"
	SecondFactorInvalidSession   = "SecondFactorInvalidSession"
	SecondFactorBadResponse      = "SecondFactorBadResponse"
	SecondFactorSuccess          = "SecondFactorSuccess"
	SecondFactorFailed           = "SecondFactorFailed"
	TokenNameRequired            = "TokenNameRequired"

	U2FRegistrationFailed    = "U2FRegistrationFailed"
	U2FRegistrationComplete  = "U2FRegistrationComplete"
	NoU2FPending             = "NoU2FPending"
	NoU2FTokenFound          = "NoU2FTokenFound"
	U2FTokenRemoved          = "U2FTokenRemoved"
	RecoveryNoRequestPending = "RecoveryNoRequestPending"

	TOTPTokenRemoved             = "TOTPTokenRemoved"
	BackupTokenOverwriteRequired = "CreateBackupTokenOverwriteRequired"
	BackupTokensRemoved          = "BackupTokensRemoved"

	// OAuth messages
	OAuthInvalidClientName  = "OAuthInvalidClientName"
	OAuthInvalidRedirect    = "OAuthInvalidRedirect"
	OAuthNoAuthorizePending = "OAuthNoAuthorizePending"
	OAuthNoTokenFound       = "OAuthNoTokenFound"
	OAuthNoGrantedScopes    = "OAuthNoGrantedScopes"
)
