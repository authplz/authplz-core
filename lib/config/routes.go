package config

// Routes object defines the paths to static pages for given actions
// For example, Routes.Login is the path to the static login page
type Routes struct {
	UserLogin  string // Login is the user login page
	UserLogout string // Logout is the user logout page
	UserCreate string // Create is the account creation page

	AccountManage string

	U2FRegister  string
	U2FManage    string
	U2FAuthorize string

	TOTPRegister  string
	TOTPManage    string
	TOTPAuthorize string

	BackupManage    string
	BackupAuthorize string

	OAuthManage    string
	OAuthCreate    string
	OauthAuthorize string // OauthAuthorize page allows users to accept or deny OAuth grants
}

// DefaultRoutes creates the default route configuration object
func DefaultRoutes() Routes {
	return Routes{
		UserLogin:  "/#/login",
		UserLogout: "/#/logout",
		UserCreate: "/#/create",

		AccountManage: "/#/account",

		U2FManage:    "/#/2fa-u2f-manage",
		U2FRegister:  "/#/2fa-u2f-register",
		U2FAuthorize: "/#/2fa-u2f-authorize",

		TOTPManage:    "/2fa-totp-manage",
		TOTPRegister:  "/2fa-totp-register",
		TOTPAuthorize: "/2fa-totp-authorize",

		BackupManage:    "/2fa-backup-manage",
		BackupAuthorize: "/2fa-backup-authorize",

		OAuthManage:    "/#/oauth-manage",
		OAuthCreate:    "/#/oauth-create",
		OauthAuthorize: "/#/oauth-authorize",
	}
}
