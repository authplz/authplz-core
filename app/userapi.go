package app

import (
	"net/http"

	"log"
)

import (
	"github.com/asaskevich/govalidator"
	"github.com/gocraft/web"
	"github.com/ryankurte/authplz/api"
)

func (c *AuthPlzTempCtx) Test(rw web.ResponseWriter, req *web.Request) {
	c.WriteApiResult(rw, api.ApiResultOk, "Test Response")
}

// Handle an action token (both get and post calls)
// This adds the action token to a session flash for use post-login attempt
func (c *AuthPlzTempCtx) Action(rw web.ResponseWriter, req *web.Request) {
	// Grab token string from get or post request
	var tokenString string
	tokenString = req.FormValue("token")
	if tokenString == "" {
		tokenString = req.URL.Query().Get("token")
	}
	if tokenString == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// If the user isn't logged in
	if c.GetUserID() == "" {
		session := c.GetSession()

		// Clear existing flashes (by reading)
		_ = session.Flashes()

		// Add token to flash and redirect
		session.AddFlash(tokenString)
		session.Save(req.Request, rw)

		c.WriteApiResult(rw, api.ApiResultOk, "Saved token")
		//TODO: redirect to login

	} else {
		//TODO: handle any active-user tokens here
		rw.WriteHeader(http.StatusNotImplemented)
	}
}

// Login to a user account
func (c *AuthPlzTempCtx) Login(rw web.ResponseWriter, req *web.Request) {
	// Fetch parameters
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	password := req.FormValue("password")
	if password == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Check user is not already logged in
	if c.GetUserID() != "" {
		c.WriteApiResult(rw, api.ApiResultOk, c.GetApiLocale().AlreadyAuthenticated)
	}

	// Attempt login via UserControl interface
	l, u, e := c.userControl.Login(email, password)
	if e != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		log.Printf("Login: user controller error %s\n", e)
		return
	}

    // TODO: handle UserControl.Login errors

    // No user account found
	user, ok := u.(UserInterface)
    if l == api.LoginFailure || !ok {
        log.Println("Login Failure: user account not found")
        rw.WriteHeader(http.StatusUnauthorized)
        return
    }

	// Load flashes and apply actions if they exist
	flashes := c.GetSession().Flashes()
	if len(flashes) > 0 {
		// Fetch token from session flash and validate
		tokenString := flashes[0].(string)
		action, err := c.tokenControl.ValidateToken(user.GetExtId(), tokenString)
		if err != nil {
			log.Printf("Login: Token error %s\n", err)
			//c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InvalidToken)
			rw.WriteHeader(http.StatusUnauthorized)
            return
		}

		// Locate token handler
		tokenHandler, ok := c.tokenHandlers[*action]
		if !ok {
			log.Printf("Login: No token handler found for action %s\n", action)
		}

		// Execute token action
		err = tokenHandler.HandleToken(user, *action)
		if err != nil {
			log.Printf("Login: Token action %s handler error %s\n", action, err)
		}

        // Reload login state
        l, _, e = c.userControl.Login(email, password)
        if e != nil {
            rw.WriteHeader(http.StatusUnauthorized)
            log.Printf("Login: user controller error %s\n", e)
            return
        }
	}

    // Handle login success
    if l == api.LoginSuccess {
        log.Println("Login: Login OK")

        // Create session
        c.LoginUser(user, rw, req)
        c.WriteApiResult(rw, api.ApiResultOk, c.GetApiLocale().LoginSuccessful)
        return
    }

	// Handle not yet activated accounts
	if l == api.LoginUnactivated {
		log.Println("Login: Account not activated")
		//TODO: prompt for activation (resend email?)
		rw.WriteHeader(http.StatusUnauthorized)
		//c.WriteApiResult(rw, api.ApiResultError, user.LoginUnactivated.Message);
		return
	}

	// TODO: handle locked accounts
	if l == api.LoginLocked {
		log.Println("Login: Account locked")
		//TODO: prompt for unlock (resend email?)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Handle partial logins (2FA)
	if l == api.LoginPartial {
		log.Println("Login: Partial login")
		//TODO: fetch tokens and set flash for 2FA
		//c.U2FBindAuthenticationRequest(rw, req, u.GetExtId())
		rw.WriteHeader(http.StatusAccepted)
		//c.WriteApiResult(rw, api.ApiResultError, api.GetApiLocale(c.locale).2FARequired);
		return
	}

	log.Printf("Login: Login failed (unknown)\n")
	rw.WriteHeader(http.StatusUnauthorized)
}

// End a user session
func (c *AuthPlzTempCtx) Logout(rw web.ResponseWriter, req *web.Request) {
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	} else {
		c.LogoutUser(rw, req)
		c.WriteApiResult(rw, api.ApiResultOk, c.GetApiLocale().LogoutSuccessful)
	}
}
