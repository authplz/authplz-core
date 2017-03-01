package user

import (
	"log"
	"net/http"
	//"encoding/json"
)

import (
	"github.com/asaskevich/govalidator"
	"github.com/gocraft/web"
	"github.com/ryankurte/authplz/api"
	"github.com/ryankurte/authplz/appcontext"
)

// API context instance
type UserApiCtx struct {
	// Base context required by router
	*appcontext.AuthPlzCtx
	// User module instance
	um *UserModule
}

// Helper middleware to bind module to API context
func BindUserContext(userModule *UserModule) func(ctx *UserApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *UserApiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.um = userModule
		next(rw, req)
	}
}

func (userModule *UserModule) BindAPI(router *web.Router) {
	// Create router for user modules
	userRouter := router.Subrouter(UserApiCtx{}, "/api")

	// Attach module context
	userRouter.Middleware(BindUserContext(userModule))

	// Bind endpoints
	userRouter.Get("/test", (*UserApiCtx).Test)
	userRouter.Get("/status", (*UserApiCtx).Status)
	userRouter.Post("/create", (*UserApiCtx).Create)
	userRouter.Get("/account", (*UserApiCtx).AccountGet)
	userRouter.Post("/account", (*UserApiCtx).AccountPost)
}

// Test endpoint
func (c *UserApiCtx) Test(rw web.ResponseWriter, req *web.Request) {
	c.WriteApiResult(rw, api.ApiResultOk, "Test Response")
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

// Fetch a user object
func (c *UserApiCtx) AccountGet(rw web.ResponseWriter, req *web.Request) {
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return

	} else {
		// Fetch user from user controller
		u, err := c.um.GetUser(c.GetUserID())
		if err != nil {
			log.Print(err)
			c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
			return
		}

		c.WriteJson(rw, u)
	}
}

// Update user object
func (c *UserApiCtx) AccountPost(rw web.ResponseWriter, req *web.Request) {
	if c.GetUserID() == "" {
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
	_, err := c.um.UpdatePassword(c.GetUserID(), oldPass, newPass)
	if err != nil {
		log.Print(err)
		c.WriteApiResult(rw, api.ApiResultError, c.GetApiLocale().InternalError)
		return
	}

	c.WriteApiResult(rw, api.ApiResultOk, c.GetApiLocale().PasswordUpdated)
}
