package app

import "fmt"
import "log"
import "net/http"
import "encoding/json"

import "github.com/gocraft/web"
import "github.com/asaskevich/govalidator"

import "github.com/ryankurte/authplz/usercontroller"
import "github.com/ryankurte/authplz/token"
import "github.com/ryankurte/authplz/datastore"
import "github.com/ryankurte/authplz/api"

// Helper to write objects out as JSON
func (ctx *AuthPlzCtx) WriteJson(w http.ResponseWriter, i interface{}) {
	js, err := json.Marshal(i)
	if err != nil {
		log.Print(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

// Helper to write API results out
func (ctx *AuthPlzCtx) WriteApiResult(w http.ResponseWriter, result string, message string) {
	apiResp := api.ApiResponse{Result: result, Message: message}
	ctx.WriteJson(w, apiResp)
}

// Create a user
func (c *AuthPlzCtx) Create(rw web.ResponseWriter, req *web.Request) {
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		log.Printf("api.Create: email parameter required")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	password := req.FormValue("password")
	if password == "" {
		log.Printf("api.Create: password parameter required")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	u, e := c.global.userController.Create(email, password)
	if e != nil {
		fmt.Fprint(rw, "Error: %s", e)
		rw.WriteHeader(500)
		return
	}

	if u == nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Println("api.Create: Create OK")

	rw.WriteHeader(http.StatusOK)
}

// Handle an action token
func (c *AuthPlzCtx) HandleToken(u *datastore.User, tokenString string, rw web.ResponseWriter, req *web.Request) (err error) {

	// Check token validity
	claims, err := c.global.tokenController.ParseToken(tokenString)
	if err != nil {
		fmt.Println("api.HandleToken: Invalid or expired token")
		rw.WriteHeader(http.StatusUnauthorized)
		return fmt.Errorf("Invalid or expired token")
	}

	if u.ExtId != claims.Subject {
		log.Println("api.HandleToken: Token subject does not match user id")
		rw.WriteHeader(http.StatusUnauthorized)
		return fmt.Errorf("Token subject does not match user id")
	}

	switch claims.Action {
	case token.TokenActionUnlock:
		log.Printf("api.HandleToken: Unlocking user\n")

		c.global.userController.Unlock(u.Email)

		// Create session
		c.LoginUser(u, rw, req)
		c.WriteApiResult(rw, api.ApiResultOk, api.ApiMessageUnlockSuccessful)
		return nil

	case token.TokenActionActivate:
		log.Printf("api.HandleToken: Activating user\n")

		c.global.userController.Activate(u.Email)

		// Create session
		c.LoginUser(u, rw, req)
		c.WriteApiResult(rw, api.ApiResultOk, api.ApiMessageActivationSuccessful)
		return nil

	default:
		log.Printf("api.HandleToken: Invalid token action\n")
		rw.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("Invalid token action")
	}
}

// Login to a user account
func (c *AuthPlzCtx) Login(rw web.ResponseWriter, req *web.Request) {
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

	// Attempt login
	l, u, e := c.global.userController.Login(email, password)
	if e != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		log.Printf("api.Login: user controller error %s\n", e)
		return
	}

	// Handle simple logins
	if l == &usercontroller.LoginSuccess {
		log.Println("api.Login: Login OK")

		// Create session
		c.LoginUser(u, rw, req)
		c.WriteApiResult(rw, api.ApiResultOk, api.ApiMessageLoginSuccess)
		return
	}

	// Load flashes if they exist
	flashes := c.session.Flashes()
	if len(flashes) > 0 {
		// Grab token and perform action
		tokenString := flashes[0].(string)

		tokenErr := c.HandleToken(u, tokenString, rw, req)
		if tokenErr == nil {
			log.Printf("api.Login: Token action complete\n")
			return
		} else {
			log.Printf("api.Login: Token error %s\n", tokenErr)
		}
	}

	// Handle not yet activated accounts
	if l == &usercontroller.LoginUnactivated {
		log.Println("api.Login: Account not activated")
		//TODO: prompt for activation (resend email?)
		rw.WriteHeader(http.StatusUnauthorized)
		//c.WriteApiResult(rw, api.ApiResultError, usercontroller.LoginUnactivated.Message);
		return
	}

	// TODO: handle locked accounts
	if l == &usercontroller.LoginLocked {
		log.Println("api.Login: Account locked")
		//TODO: prompt for unlock (resend email?)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Handle partial logins (2FA)
	if l == &usercontroller.LoginPartial {
		log.Println("api.Login: Partial login")
		//TODO: fetch tokens and set flash for 2FA
		c.U2FBindAuthenticationRequest(rw, req, u.ExtId)
		rw.WriteHeader(http.StatusAccepted)
		//c.WriteApiResult(rw, api.ApiResultError, api.ApiMessage2FARequired);
		return
	}

	log.Printf("api.Login: Login failed\n")
	rw.WriteHeader(http.StatusUnauthorized)
}

// Handle an action token (both get and post calls)
func (c *AuthPlzCtx) Action(rw web.ResponseWriter, req *web.Request) {
	// Grab token string from get or post request
	var tokenString string
	tokenString = req.FormValue("token")
	if tokenString == "" {
		req.URL.Query().Get("token")
	}
	if tokenString == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// If the user isn't logged in
	if c.userid == "" {
		// Clear existing flashes (by reading)
		_ = c.session.Flashes()

		// Add token to flash and redirect
		c.session.AddFlash(tokenString)
		c.session.Save(req.Request, rw)

		c.WriteApiResult(rw, api.ApiResultOk, "Saved token")
		//TODO: redirect to login

	} else {
		//TODO: handle any active-user tokens here
		rw.WriteHeader(http.StatusNotImplemented)
	}
}

// Get user login status
func (c *AuthPlzCtx) Status(rw web.ResponseWriter, req *web.Request) {
	if c.userid == "" {
		c.WriteApiResult(rw, api.ApiResultError, api.ApiMessageUnauthorized)
	} else {
		c.WriteApiResult(rw, api.ApiResultOk, api.ApiMessageLoginSuccess)
	}
}

// Get user object
func (c *AuthPlzCtx) AccountGet(rw web.ResponseWriter, req *web.Request) {
	if c.userid == "" {
		c.WriteApiResult(rw, api.ApiResultError, api.ApiMessageUnauthorized)

	} else {
		// Fetch user from user controller
		u, err := c.global.userController.GetUser(c.userid)
		if err != nil {
			log.Print(err)
			c.WriteApiResult(rw, api.ApiResultError, api.ApiMessageInternalError)
			return
		}

		c.WriteJson(rw, u)
	}
}

// Get user object
func (c *AuthPlzCtx) AccountPost(rw web.ResponseWriter, req *web.Request) {
	if c.userid == "" {
		c.WriteApiResult(rw, api.ApiResultError, api.ApiMessageUnauthorized)

	} else {
		// Fetch user from user controller
		u, err := c.global.userController.GetUser(c.userid)
		if err != nil {
			log.Print(err)
			c.WriteApiResult(rw, api.ApiResultError, api.ApiMessageInternalError)
			return
		}

		c.WriteJson(rw, u)
	}
}

// End a user session
func (c *AuthPlzCtx) Logout(rw web.ResponseWriter, req *web.Request) {
	if c.userid == "" {
		c.WriteApiResult(rw, api.ApiResultError, api.ApiMessageUnauthorized)
	} else {
		c.LogoutUser(rw, req)
		c.WriteApiResult(rw, api.ApiResultOk, api.ApiMessageLogoutSuccess)
	}
}

// Test endpoint
func (c *AuthPlzCtx) Test(rw web.ResponseWriter, req *web.Request) {
	// Get the previously flashes, if any.
	if flashes := c.session.Flashes(); len(flashes) > 0 {
		log.Printf("Flashes: %+v\n", flashes)
	} else {
		// Set a new flash.
		c.session.AddFlash("Hello, flash messages world!")
	}
	c.session.Save(req.Request, rw)
	c.WriteApiResult(rw, api.ApiResultOk, "Test Response")
}
