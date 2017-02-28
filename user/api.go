package user

import (
	"fmt"
	"log"
	"net/http"
	//"encoding/json"
)

import (
	"github.com/asaskevich/govalidator"
	"github.com/gocraft/web"
	"github.com/ryankurte/authplz/api"
	"github.com/ryankurte/authplz/appcontext"
	"github.com/ryankurte/authplz/token"
)

// API context instance
type UserApiCtx struct {
	// Base context required by router
	*appcontext.AuthPlzCtx
	// User module instance
	um *UserModule
}

func BindUserContext(userModule *UserModule) func(ctx *UserApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *UserApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.um = userModule
		next(rw, req)
	}
}

func (userModule *UserModule) Bind(router *web.Router) {
	// Create router for user modules
	userRouter := router.Subrouter(UserApiCtx{}, "/api")

	// Attach module context
	userRouter.Middleware(BindUserContext(userModule))

	// Bind endpoints
	userRouter.Get("/status", (*UserApiCtx).Status)
	userRouter.Post("/create", (*UserApiCtx).Create)
}

// Get user login status
func (c *UserApiCtx) Status(rw web.ResponseWriter, req *web.Request) {
	if c.GetUserID() == "" {
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiMessageInst().Unauthorized)
	} else {
		c.WriteApiResult(rw, api.ApiResultOk, c.GetApiMessageInst().LoginSuccessful)
	}
}

func (c *UserApiCtx) Create(rw web.ResponseWriter, req *web.Request) {
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

	u, e := c.um.Create(email, password)
	if e != nil {
		log.Printf("Create: user creation failed with %s", e)

		if e == ErrorDuplicateAccount {
			c.WriteApiResult(rw, api.ApiResultOk, c.GetApiMessageInst().CreateUserSuccess)
			return
		} else if e == ErrorPasswordTooShort {
			c.WriteApiResult(rw, api.ApiResultError, c.GetApiMessageInst().PasswordComplexityTooLow)
			return
		}

		c.WriteApiResult(rw, api.ApiResultError, c.GetApiMessageInst().InternalError)
		return
	}

	if u == nil {
		log.Printf("Create: user creation failed")
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiMessageInst().InternalError)
		return
	}

	log.Println("Create: Create OK")

	c.WriteApiResult(rw, api.ApiResultOk, c.GetApiMessageInst().CreateUserSuccess)
}

// Generic method to handle an action token
func (c *UserApiCtx) HandleToken(u UserInterface, tokenString string, rw web.ResponseWriter, req *web.Request) (err error) {

	// Check token validity
	claims, err := c.um.tokenControl.ParseToken(tokenString)
	if err != nil {
		log.Println("HandleToken: Invalid or expired token")
		rw.WriteHeader(http.StatusUnauthorized)
		return fmt.Errorf("Invalid or expired token")
	}

	if u.GetExtId() != claims.Subject {
		log.Println("HandleToken: Token subject does not match user id")
		rw.WriteHeader(http.StatusUnauthorized)
		return fmt.Errorf("Token subject does not match user id")
	}

	switch claims.Action {
	case token.TokenActionUnlock:
		log.Printf("HandleToken: Unlocking user\n")

		c.um.Unlock(u.GetEmail())

		// Create session
		c.LoginUser(u, rw, req)
		c.WriteApiResult(rw, api.ApiResultOk, c.GetApiMessageInst().UnlockSuccessful)
		return nil

	case token.TokenActionActivate:
		log.Printf("HandleToken: Activating user\n")

		c.um.Activate(u.GetEmail())

		// Create session
		c.LoginUser(u, rw, req)
		c.WriteApiResult(rw, api.ApiResultOk, c.GetApiMessageInst().ActivationSuccessful)
		return nil

	default:
		log.Printf("HandleToken: Invalid token action\n")
		rw.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("Invalid token action")
	}
}
