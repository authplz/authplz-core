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

// swagger:route POST /create createUser
//
// Create a user account
//
//
//     Consumes:
//     - application/x-www-form-urlencoded
//
//     Produces:
//     - application/json
//
//     Responses:
//       200: apiResponse
//       400: badRequestResponse
//		 401: unauthorizedResponse
func (c *AuthPlzCtx) Create(rw web.ResponseWriter, req *web.Request) {
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		log.Printf("Create: email parameter required")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	password := req.FormValue("password")
	if password == "" {
		log.Printf("Create: password parameter required")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	u, e := c.global.userController.Create(email, password)
	if e != nil {
		log.Printf("Create: user creation failed with %s", e)

		if e == usercontroller.ErrorDuplicateAccount {
			c.WriteApiResult(rw, api.ApiResultOk, api.GetApiLocale(c.locale).CreateUserSuccess)
			return
		} else if e == usercontroller.ErrorPasswordTooShort {
			c.WriteApiResult(rw, api.ApiResultError, api.GetApiLocale(c.locale).PasswordComplexityTooLow)
			return
		}

		c.WriteApiResult(rw, api.ApiResultError, api.GetApiLocale(c.locale).InternalError)
		return
	}

	if u == nil {
		log.Printf("Create: user creation failed")
		c.WriteApiResult(rw, api.ApiResultError, api.GetApiLocale(c.locale).InternalError)
		return
	}

	log.Println("Create: Create OK")

	c.WriteApiResult(rw, api.ApiResultOk, api.GetApiLocale(c.locale).CreateUserSuccess)
}

// Parameters for the create user endpoint
// swagger:parameters createUser
type CreateUserParams struct {
	// required: true
	email string
	// required: true
	password string
}

// Handle an action token
func (c *AuthPlzCtx) HandleToken(u *datastore.User, tokenString string, rw web.ResponseWriter, req *web.Request) (err error) {

	// Check token validity
	claims, err := c.global.tokenController.ParseToken(tokenString)
	if err != nil {
		fmt.Println("HandleToken: Invalid or expired token")
		rw.WriteHeader(http.StatusUnauthorized)
		return fmt.Errorf("Invalid or expired token")
	}

	if u.ExtId != claims.Subject {
		log.Println("HandleToken: Token subject does not match user id")
		rw.WriteHeader(http.StatusUnauthorized)
		return fmt.Errorf("Token subject does not match user id")
	}

	switch claims.Action {
	case token.TokenActionUnlock:
		log.Printf("HandleToken: Unlocking user\n")

		c.global.userController.Unlock(u.Email)

		// Create session
		c.LoginUser(u, rw, req)
		c.WriteApiResult(rw, api.ApiResultOk, api.GetApiLocale(c.locale).UnlockSuccessful)
		return nil

	case token.TokenActionActivate:
		log.Printf("HandleToken: Activating user\n")

		c.global.userController.Activate(u.Email)

		// Create session
		c.LoginUser(u, rw, req)
		c.WriteApiResult(rw, api.ApiResultOk, api.GetApiLocale(c.locale).ActivationSuccessful)
		return nil

	default:
		log.Printf("HandleToken: Invalid token action\n")
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

	if c.userid != "" {
		c.WriteApiResult(rw, api.ApiResultOk, api.GetApiLocale(c.locale).AlreadyAuthenticated)
	}

	// Attempt login
	l, u, e := c.global.userController.Login(email, password)
	if e != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		log.Printf("Login: user controller error %s\n", e)
		return
	}

	// Handle simple logins
	if l == &usercontroller.LoginSuccess {
		log.Println("Login: Login OK")

		// Create session
		c.LoginUser(u, rw, req)
		c.WriteApiResult(rw, api.ApiResultOk, api.GetApiLocale(c.locale).LoginSuccessful)
		return
	}

	// Load flashes if they exist
	flashes := c.session.Flashes()
	if len(flashes) > 0 {
		// Grab token and perform action
		tokenString := flashes[0].(string)

		tokenErr := c.HandleToken(u, tokenString, rw, req)
		if tokenErr == nil {
			log.Printf("Login: Token action complete\n")
			return
		} else {
			log.Printf("Login: Token error %s\n", tokenErr)
		}
	}

	// Handle not yet activated accounts
	if l == &usercontroller.LoginUnactivated {
		log.Println("Login: Account not activated")
		//TODO: prompt for activation (resend email?)
		rw.WriteHeader(http.StatusUnauthorized)
		//c.WriteApiResult(rw, api.ApiResultError, usercontroller.LoginUnactivated.Message);
		return
	}

	// TODO: handle locked accounts
	if l == &usercontroller.LoginLocked {
		log.Println("Login: Account locked")
		//TODO: prompt for unlock (resend email?)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Handle partial logins (2FA)
	if l == &usercontroller.LoginPartial {
		log.Println("Login: Partial login")
		//TODO: fetch tokens and set flash for 2FA
		c.U2FBindAuthenticationRequest(rw, req, u.ExtId)
		rw.WriteHeader(http.StatusAccepted)
		//c.WriteApiResult(rw, api.ApiResultError, api.GetApiLocale(c.locale).2FARequired);
		return
	}

	log.Printf("Login: Login failed\n")
	rw.WriteHeader(http.StatusUnauthorized)
}

// Handle an action token (both get and post calls)
func (c *AuthPlzCtx) Action(rw web.ResponseWriter, req *web.Request) {
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
		c.WriteApiResult(rw, api.ApiResultError, api.GetApiLocale(c.locale).Unauthorized)
	} else {
		c.WriteApiResult(rw, api.ApiResultOk, api.GetApiLocale(c.locale).LoginSuccessful)
	}
}

func (c *AuthPlzCtx) AccountGet(rw web.ResponseWriter, req *web.Request) {
	if c.userid == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return

	} else {
		// Fetch user from user controller
		u, err := c.global.userController.GetUser(c.userid)
		if err != nil {
			log.Print(err)
			c.WriteApiResult(rw, api.ApiResultError, api.GetApiLocale(c.locale).InternalError)
			return
		}

		c.WriteJson(rw, u)
	}
}

// Get user object
func (c *AuthPlzCtx) AccountPost(rw web.ResponseWriter, req *web.Request) {
	if c.userid == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Fetch password arguments
	oldPass := req.FormValue("old_password")
	if oldPass == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	newPass := req.FormValue("new_password")
	if newPass == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Update password
	_, err := c.global.userController.UpdatePassword(c.userid, oldPass, newPass)
	if err != nil {
		log.Print(err)
		c.WriteApiResult(rw, api.ApiResultError, api.GetApiLocale(c.locale).InternalError)
		return
	}

	c.WriteApiResult(rw, api.ApiResultOk, api.GetApiLocale(c.locale).PasswordUpdated)
}

// End a user session
func (c *AuthPlzCtx) Logout(rw web.ResponseWriter, req *web.Request) {
	if c.userid == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	} else {
		c.LogoutUser(rw, req)
		c.WriteApiResult(rw, api.ApiResultOk, api.GetApiLocale(c.locale).LogoutSuccessful)
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
