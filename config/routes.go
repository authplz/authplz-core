package config

// Routes object defines the paths to static pages for given actions
// For example, Routes.Login is the path to the static login page
type Routes struct {
	Login  string // Login is the user login page
	Logout string // Logout is the user logout page

	OauthAuthorize string // OauthAuthorize page allows users to accept or deny OAuth grants
}

// DefaultRoutes creates the default route configuration object
func DefaultRoutes() Routes {
	return Routes{
		Login:  "/login",
		Logout: "/logout",

		OauthAuthorize: "/oauth/authorize",
	}
}
