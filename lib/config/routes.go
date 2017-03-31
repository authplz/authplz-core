package config

// Routes object defines the paths to static pages for given actions
// For example, Routes.Login is the path to the static login page
type Routes struct {
	Login  string // Login is the user login page
	Logout string // Logout is the user logout page

	AccountManage string

	U2FRegister  string
	U2FManage    string
	U2FAuthorize string

	TOTPRegister  string
	TOTPManage    string
	TOTPAuthorize string

	OAuthManage    string
	OauthAuthorize string // OauthAuthorize page allows users to accept or deny OAuth grants
}

// DefaultRoutes creates the default route configuration object
func DefaultRoutes() Routes {
	return Routes{
		Login:  "/login",
		Logout: "/logout",

		AccountManage: "/account",

		U2FRegister:  "/u2f/register",
		U2FManage:    "/u2f/manage",
		U2FAuthorize: "/u2f/authorize",

		TOTPRegister:  "/totp/register",
		TOTPManage:    "/totp/manage",
		TOTPAuthorize: "/totp/authorize",

		OAuthManage:    "/oauth/manage",
		OauthAuthorize: "/oauth/authorize",
	}
}
