package user

import (
	"log"
	"net/http"
	"regexp"
	"strings"
	//"encoding/json"
)

import (
	"github.com/asaskevich/govalidator"
	"github.com/gocraft/web"
	"github.com/ryankurte/authplz/api"
	"github.com/ryankurte/authplz/appcontext"
)

// API context instance
type apiCtx struct {
	// Base context required by router
	*appcontext.AuthPlzCtx
	// User module instance
	um *Controller
}

// BindUserContext Helper middleware to bind module to API context
func BindUserContext(userModule *Controller) func(ctx *apiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	return func(ctx *apiCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.um = userModule
		next(rw, req)
	}
}

// BindAPI Binds the API for the user module to the provided router
func (userModule *Controller) BindAPI(router *web.Router) {
	// Create router for user modules
	userRouter := router.Subrouter(apiCtx{}, "/api")

	// Attach module context
	userRouter.Middleware(BindUserContext(userModule))

	// Bind endpoints
	userRouter.Get("/test", (*apiCtx).Test)
	userRouter.Get("/status", (*apiCtx).Status)
	userRouter.Post("/create", (*apiCtx).Create)
	userRouter.Get("/account", (*apiCtx).AccountGet)
	userRouter.Post("/account", (*apiCtx).AccountPost)
	userRouter.Post("/reset", (*apiCtx).ResetPost)
}

// Test endpoint
func (c *apiCtx) Test(rw web.ResponseWriter, req *web.Request) {
	c.WriteApiResult(rw, api.ResultOk, "Test Response")
}

// Get user login status
func (c *apiCtx) Status(rw web.ResponseWriter, req *web.Request) {
	if c.GetUserID() == "" {
		c.WriteApiResult(rw, api.ResultError, c.GetApiMessageInst().Unauthorized)
	} else {
		c.WriteApiResult(rw, api.ResultOk, c.GetApiMessageInst().LoginSuccessful)
	}
}

var usernameExp = regexp.MustCompile(`([a-z0-9\.]+)`)

func (c *apiCtx) Create(rw web.ResponseWriter, req *web.Request) {
	email := strings.ToLower(req.FormValue("email"))
	if !govalidator.IsEmail(email) {
		log.Printf("Create: email parameter required")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	username := strings.ToLower(req.FormValue("username"))
	if !usernameExp.MatchString(username) {
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

	u, e := c.um.Create(email, username, password)
	if e != nil {
		log.Printf("Create: user creation failed with %s", e)

		if e == ErrorDuplicateAccount {
			c.WriteApiResult(rw, api.ResultOk, c.GetApiMessageInst().CreateUserSuccess)
			return
		} else if e == ErrorPasswordTooShort {
			c.WriteApiResult(rw, api.ResultError, c.GetApiMessageInst().PasswordComplexityTooLow)
			return
		}

		c.WriteApiResult(rw, api.ResultError, c.GetApiMessageInst().InternalError)
		return
	}

	if u == nil {
		log.Printf("Create: user creation failed")
		c.WriteApiResult(rw, api.ResultError, c.GetApiMessageInst().InternalError)
		return
	}

	log.Println("Create: Create OK")

	c.WriteApiResult(rw, api.ResultOk, c.GetApiMessageInst().CreateUserSuccess)
}

// Fetch a user object
func (c *apiCtx) AccountGet(rw web.ResponseWriter, req *web.Request) {
	if c.GetUserID() == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		return

	}
	// Fetch user from user controller
	u, err := c.um.GetUser(c.GetUserID())
	if err != nil {
		log.Print(err)
		c.WriteApiResult(rw, api.ResultError, c.GetApiLocale().InternalError)
		return
	}

	c.WriteJson(rw, u)

}

// Update user object
func (c *apiCtx) AccountPost(rw web.ResponseWriter, req *web.Request) {
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
		c.WriteApiResult(rw, api.ResultError, c.GetApiLocale().InternalError)
		return
	}

	c.WriteApiResult(rw, api.ResultOk, c.GetApiLocale().PasswordUpdated)
}

// ResetPost handles password reset posts
func (c *apiCtx) ResetPost(rw web.ResponseWriter, req *web.Request) {
	if c.GetUserID() != "" {
		log.Printf("UserModule.ResetPost user already logged in")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Fetch user recovery request userid
	userid := c.GetRecoveryRequest(rw, req)
	if userid == "" {
		log.Printf("UserModule.ResetPost no recovery request found")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Fetch new user password
	password := req.FormValue("password")
	if password == "" {
		log.Printf("UserModule.ResetPost missing password")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Update password
	_, err := c.um.SetPassword(c.GetUserID(), password)
	if err != nil {
		log.Printf("UserAPI.ResetPost error setting password (%s)", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Write OK response
	c.WriteApiResult(rw, api.ResultOk, c.GetApiLocale().PasswordUpdated)
}
