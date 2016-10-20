package main

import "os"

//import "strings"
import "fmt"
import "log"
import "net/http"

import "encoding/json"
import "encoding/gob"

import "github.com/gocraft/web"

//import "github.com/kataras/iris"
import "github.com/gorilla/sessions"
import "github.com/gorilla/context"

import "github.com/asaskevich/govalidator"

import "github.com/ryankurte/authplz/usercontroller"
import "github.com/ryankurte/authplz/token"
import "github.com/ryankurte/authplz/datastore"


// Application global context
// TODO: this could be split and bound by module
type AuthPlzGlobalCtx struct {
	port            string
	address         string
	userController  *usercontroller.UserController
	tokenController *token.TokenController
	sessionStore    *sessions.CookieStore
}

// Application handler context
type AuthPlzCtx struct {
	global  *AuthPlzGlobalCtx
	session *sessions.Session
	userid  string
}

// Convenience type to describe middleware functions
type MiddlewareFunc func(ctx *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc)

// Bind global context object into the router context
func BindContext(globalCtx *AuthPlzGlobalCtx) MiddlewareFunc {
	return func(ctx *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		ctx.global = globalCtx
		next(rw, req)
	}
}

// User session layer
func (ctx *AuthPlzCtx) SessionMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	session, err := ctx.global.sessionStore.Get(req.Request, "user-session")
	if err != nil {
		log.Print(err)
		next(rw, req)
		return
	}

	// Save session for further use
	ctx.session = session

	// Load user from session if set
	// TODO: this will be replaced with sessions when implemented
	if session.Values["userId"] != nil {
		fmt.Println("userId found")
		//TODO: find user account
		ctx.userid = session.Values["userId"].(string)
	}

	//session.Save(r, w)
	next(rw, req)
}

func (c *AuthPlzCtx) RequireAccountMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	if c.userid == "" {
		c.WriteApiResult(rw, ApiResultError, "You must be signed in to view this page")
	} else {
		next(rw, req)
	}
}

func (ctx *AuthPlzCtx) WriteApiResult(w http.ResponseWriter, result string, message string) {
	apiResp := ApiResponse{Result: result, Message: message}

	js, err := json.Marshal(apiResp)
	if err != nil {
		log.Print(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}


// Create a user
func (c *AuthPlzCtx) Create(rw web.ResponseWriter, req *web.Request) {
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		fmt.Printf("email parameter required")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	password := req.FormValue("password")
	if password == "" {
		fmt.Printf("password parameter required")
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

	log.Println("Login OK")

	rw.WriteHeader(http.StatusOK)
}

// Login to a user account
func (c *AuthPlzCtx) Login(rw web.ResponseWriter, req *web.Request) {
	// Fetch parameters
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Println("email parameter required")
		return
	}
	password := req.FormValue("password")
	if password == "" {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Println("password parameter required")
		return
	}

	// Attempt login
	l, u, e := c.global.userController.Login(email, password)
	if e != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		fmt.Printf("Error: %s", e)
		return
	}

	// Handle simple logins
	if l == &usercontroller.LoginSuccess {
		log.Println("Login OK")

		// Create session
		c.session.Values["userId"] = u.UUID
		c.session.Save(req.Request, rw)

		c.WriteApiResult(rw, ApiResultOk, ApiMessageLoginSuccess)
		return
	}

	// Load flashes if they exist
	flashes := c.session.Flashes()

	// Handle not yet activated accounts
	if l == &usercontroller.LoginUnactivated {
		if len(flashes) > 0 {
			activateToken := flashes[0]

			claims, err := c.global.tokenController.ParseToken(activateToken.(string))
			if err != nil {
				fmt.Printf("Invalid token\n")
				c.WriteApiResult(rw, ApiResultError, ApiMessageInvalidToken)
				return
			}

			fmt.Printf("Valid token found\n")
			if claims.Action == token.TokenActionActivate {
				fmt.Printf("Activation token\n")

				if u.UUID == claims.Subject {
					fmt.Printf("Activating user\n")

					c.global.userController.Activate(u.Email)

					// Create session
					c.session.Values["userId"] = u.UUID
					c.session.Save(req.Request, rw)

					c.WriteApiResult(rw, ApiResultOk, ApiMessageActivationSuccessful)

				} else {
					fmt.Printf("Subject mismatch user\n")
				}

			} else {
				fmt.Printf("Invalid token\n")
				rw.WriteHeader(http.StatusBadRequest)
				return
			}

			rw.WriteHeader(http.StatusOK)

		} else {
			log.Println("Account not activated")
			//TODO: prompt for activation (resend email?)
			rw.WriteHeader(http.StatusUnauthorized)
			//c.WriteApiResult(rw, ApiResultError, usercontroller.LoginUnactivated.Message);
		}

		return
	}

	// TODO: handle disabled accounts
	if l == &usercontroller.LoginDisabled {

	}

	// Handle partial logins (2FA)
	if l == &usercontroller.LoginPartial {
		log.Println("Partial login")
		//TODO: fetch tokens and set flash
		rw.WriteHeader(http.StatusNotImplemented)
		return
	}

	fmt.Printf("login endpoint: login failed %s", e)
	rw.WriteHeader(http.StatusUnauthorized)
}

func (c *AuthPlzCtx) Action(rw web.ResponseWriter, req *web.Request) {

	// Grab token string from get or post request
	var tokenString string
	tokenString = req.FormValue("token")
	if tokenString == "" {
		req.URL.Query().Get("token")
	}
	if tokenString == "" {
		rw.WriteHeader(http.StatusBadRequest)
		fmt.Println("token parameter required")
		return
	}

	// If the user isn't logged in
	if c.userid == "" {
		fmt.Printf("Received token, login required (saving to flash)\n")

		// Clear existing flashes (by reading)
		_ = c.session.Flashes()

		// Add token to flash and redirect
		c.session.AddFlash(tokenString)
		c.session.Save(req.Request, rw)

		c.WriteApiResult(rw, ApiResultOk, "Saved token")
		//TODO: redirect to login

	} else {
		// Check token validity
		claims, err := c.global.tokenController.ParseToken(tokenString)
		if err != nil {
			fmt.Printf("Invalid token\n")
			c.WriteApiResult(rw, ApiResultError, "Invalid token")
			return
		}

		fmt.Printf("Valid token found (claims: %+v)\n", claims)
		//TODO: execute action token on signed in user
		rw.WriteHeader(http.StatusOK)
	}
}

// Logout of a user account
func (c *AuthPlzCtx) Test(rw web.ResponseWriter, req *web.Request) {
	// Get the previously flashes, if any.
	if flashes := c.session.Flashes(); len(flashes) > 0 {
		fmt.Printf("Flashes: %+v\n", flashes)
	} else {
		// Set a new flash.
		c.session.AddFlash("Hello, flash messages world!")
	}
	c.session.Save(req.Request, rw)
	c.WriteApiResult(rw, ApiResultOk, "Test Response")
}

// Get user login status
func (c *AuthPlzCtx) Status(rw web.ResponseWriter, req *web.Request) {
	if c.userid == "" {
		c.WriteApiResult(rw, ApiResultError, "You must be signed in to view this page")
	} else {
		c.WriteApiResult(rw, ApiResultOk, "Signed in")
	}
}

// Get user login status
func (c *AuthPlzCtx) Logout(rw web.ResponseWriter, req *web.Request) {
	if c.userid == "" {
		c.WriteApiResult(rw, ApiResultError, "You must be signed sign out")
	} else {
		c.session.Options.MaxAge = -1
		c.session.Save(req.Request, rw)
		c.WriteApiResult(rw, ApiResultOk, ApiMessageLogoutSuccess)
	}
}

type AuthPlzServer struct {
	address string
	port    string
	ds      datastore.DataStore
	ctx     AuthPlzGlobalCtx
	router  *web.Router
}

func NewServer(address string, port string, db string) *AuthPlzServer {
	server := AuthPlzServer{}

	server.address = address
	server.port = port

	gob.Register(&token.TokenClaims{})

	// Attempt database connection
	server.ds = datastore.NewDataStore(db)

	// Create session store
	sessionStore := sessions.NewCookieStore([]byte("something-very-secret"))

	// Create controllers
	uc := usercontroller.NewUserController(&(server.ds), nil)
	tc := token.NewTokenController(server.address, "something-also-secret")

	// Create a global context object
	server.ctx = AuthPlzGlobalCtx{port, address, &uc, &tc, sessionStore}

	// Create router
	server.router = web.New(AuthPlzCtx{}).
		Middleware(BindContext(&server.ctx)).
		Middleware(web.LoggerMiddleware).
		Middleware(web.ShowErrorsMiddleware).
		Middleware((*AuthPlzCtx).SessionMiddleware).
		Post("/api/login", (*AuthPlzCtx).Login).
		Post("/api/create", (*AuthPlzCtx).Create).
		Post("/api/action", (*AuthPlzCtx).Action).
		Get("/api/action", (*AuthPlzCtx).Action).
		Get("/api/logout", (*AuthPlzCtx).Logout).
		Get("/api/status", (*AuthPlzCtx).Status).
		Get("/api/test", (*AuthPlzCtx).Test)

	return &server
}

func (server *AuthPlzServer) Start() {
	// Start listening
	fmt.Println("Listening at: " + server.port)
	log.Fatal(http.ListenAndServe(server.address+":"+server.port, context.ClearHandler(server.router)))
}

func (server *AuthPlzServer) Close() {
	server.ds.Close()
}

func main() {
	var port string = "9000"
	var address string = "localhost"
	var dbString string = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Parse environmental variables
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}

	server := NewServer(address, port, dbString)

	server.Start()
}
