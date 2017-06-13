package config

// RouteConfig object defines the paths to static pages for given actions
// For example, Routes.Login is the path to the static login page
type RouteConfig struct {
	// Login is the user login page
	UserLogin string `yaml:"user-login"`
	// Logout is the user logout page
	UserLogout string `yaml:"user-logout"`
	// Create is the account creation page
	UserCreate string `yaml:"user-create"`

	// AccountManage is the user account management page
	AccountManage string `yaml:"account-manage"`

	// U2FRegister is the new u2f device registration page
	U2FRegister string `yaml:"u2f-register"`
	// U2FManage is the u2f device management page
	U2FManage string `yaml:"u2f-manage"`
	// U2FAuthorize is the u2f authorization (2fa second stage) page
	U2FAuthorize string `yaml:"u2f-authorize"`

	// TOTPRegister is the new totp code registration page
	TOTPRegister string `yaml:"totp-register"`
	// TOTPManage is the totp code management page
	TOTPManage string `yaml:"totp-manage"`
	// TOTPAuthorize is the totp code authorization (2fa second stage) page
	TOTPAuthorize string `yaml:"totp-authorize"`

	// BackupManage is the backup code management page
	BackupManage string `yaml:"backup-manage"`
	// BackupAuthorize is the backup code authorization (2fa second stage) page
	BackupAuthorize string `yaml:"backup-authorize"`

	// OAuthManage page allows users to manage OAuth grants
	OAuthManage string `yaml:"oauth-manage"`
	// OAuthCreate page allows users to create oauth clients
	OAuthCreate string `yaml:"oauth-create"`
	// OauthAuthorize page allows users to accept or deny OAuth grants
	OauthAuthorize string `yaml:"oauth-authorize"`
}

// DefaultRoutes creates the default route configuration object
func DefaultRoutes() RouteConfig {
	return RouteConfig{
		UserLogin:  "/#/login",
		UserLogout: "/#/logout",
		UserCreate: "/#/create",

		AccountManage: "/#/account",

		U2FManage:    "/#/2fa-u2f-manage",
		U2FRegister:  "/#/2fa-u2f-register",
		U2FAuthorize: "/#/2fa-u2f-authorize",

		TOTPManage:    "/#/2fa-totp-manage",
		TOTPRegister:  "/#/2fa-totp-register",
		TOTPAuthorize: "/#/2fa-totp-authorize",

		BackupManage:    "/#/2fa-backup-manage",
		BackupAuthorize: "/#/2fa-backup-authorize",

		OAuthManage:    "/#/oauth-manage",
		OAuthCreate:    "/#/oauth-create",
		OauthAuthorize: "/#/oauth-authorize",
	}
}
