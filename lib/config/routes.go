package config

type UserRoutes struct {
	// Login is the user login page
	Login string `yaml:"login"`
	// Logout is the user logout page
	Logout string `yaml:"logout"`
	// Create is the account creation page
	Create string `yaml:"create"`
}

type AccountRoutes struct {
	// AccountManage is the user account management page
	Manage string `yaml:"manage"`
}

type SecondFactorRoutes struct {
	// Register is the new 2fa device registration page
	Register string `yaml:"register"`
	// Manage is the 2fa device management page
	Manage string `yaml:"manage"`
	// Authorize is the 2fa authorization (2fa second stage) page
	Authorize string `yaml:"authorize"`
}

type OAuthRoutes struct {
	// Manage page allows users to manage OAuth grants
	Manage string `yaml:"manage"`
	// Create page allows users to create oauth clients
	Create string `yaml:"create"`
	// Authorize page allows users to accept or deny OAuth grants
	Authorize string `yaml:"authorize"`
}

// RouteConfig object defines the paths to static pages for given actions
// For example, Routes.Login is the path to the static login page
type RouteConfig struct {
	// User routes
	User UserRoutes `yaml:"user"`

	// Account management routes
	Account AccountRoutes `yaml:"account"`

	// U2F Route Config
	U2F SecondFactorRoutes `yaml:"u2f"`
	// TOTP Route config
	TOTP SecondFactorRoutes `yaml:"totp"`
	// Backup code route config
	Backup SecondFactorRoutes `yaml:"backup"`

	// OAuth route config
	OAuth OAuthRoutes `yaml:"oauth"`
}

// DefaultRoutes creates the default route configuration object
func DefaultRoutes() RouteConfig {
	return RouteConfig{
		User: UserRoutes{
			Login:  "/#/login",
			Logout: "/#/logout",
			Create: "/#/create",
		},
		Account: AccountRoutes{Manage: "/#/account"},
		U2F: SecondFactorRoutes{
			Manage:    "/#/2fa-u2f-manage",
			Register:  "/#/2fa-u2f-register",
			Authorize: "/#/2fa-u2f-authorize",
		},
		TOTP: SecondFactorRoutes{
			Manage:    "/#/2fa-totp-manage",
			Register:  "/#/2fa-totp-register",
			Authorize: "/#/2fa-totp-authorize",
		},
		Backup: SecondFactorRoutes{
			Manage:    "/#/2fa-backup-manage",
			Authorize: "/#/2fa-backup-authorize",
		},
		OAuth: OAuthRoutes{
			Manage:    "/#/oauth-manage",
			Create:    "/#/oauth-create",
			Authorize: "/#/oauth-authorize",
		},
	}
}
