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

type ApiResponse struct {
	result  string
	message string
}

const ApiResultOk string = "ok"
const ApiResultError string = "error"

func (ctx *AuthPlzCtx) WriteApiResult(w http.ResponseWriter, result string, message string) {
	apiResp := ApiResponse{result: result, message: message}

	js, err := json.Marshal(apiResp)
	if err != nil {
		log.Print(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

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
	if session.Values["sessionId"] != nil {
		fmt.Println("sessionId found")
		//TODO: find user account
	}

	//session.Save(r, w)
	next(rw, req)
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
	// Check parameters
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
	l, e := c.global.userController.Login(email, password)
	if e != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		fmt.Printf("Error: %s", e)
		return
	}

	if l == &usercontroller.LoginPartial {
		log.Println("Partial login")
		//TODO: fetch tokens and set flash
		rw.WriteHeader(http.StatusNotImplemented)
		return
	}

	if l == &usercontroller.LoginUnactivated {
		flashes := c.session.Flashes()
		fmt.Printf("Flashes: %+v\n", flashes);

		if len(flashes) > 0 {
			activateToken := flashes[0]

			fmt.Printf("Checking token validity %s\n", activateToken)

			claims, err := c.global.tokenController.ParseToken(activateToken.(string))
			if err != nil {
				fmt.Printf("Invalid token\n")
				c.WriteApiResult(rw, ApiResultError, "Invalid token")
				return
			}

			fmt.Printf("Valid token found\n")
			switch claims.Action {
			case token.TokenActionActivate:
				fmt.Printf("Activation token\n")
			default:
				fmt.Printf("Unrecognised token\n")
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

	// Check login status
	if l == &usercontroller.LoginSuccess {
		log.Println("Login OK")
		rw.WriteHeader(http.StatusOK)
		return
	}

	fmt.Printf("login endpoint: login failed %s", e)
	rw.WriteHeader(http.StatusUnauthorized)
}

func (c *AuthPlzCtx) Action(rw web.ResponseWriter, req *web.Request) {
	// Fetch the relevant token
	var tokenString string;

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
		fmt.Printf("Received token, login required (saving to flash)\n", tokenString)
		// Add token to flash and redirect
		c.session.AddFlash(tokenString)
		c.session.Save(req.Request, rw)

		c.WriteApiResult(rw, ApiResultOk, "Saved token")

		//TODO: redirect to login

	} else {
		// TODO: Apply token
		fmt.Printf("Checking token validity %s\n", tokenString)

		claims, err := c.global.tokenController.ParseToken(tokenString)
		if err != nil {
			fmt.Printf("Invalid token %s\n", tokenString)
			c.WriteApiResult(rw, ApiResultError, "Invalid token")
			return
		}

		fmt.Printf("Valid token found %s\n", tokenString)
		switch claims.Action {
		case token.TokenActionActivate:
			fmt.Printf("Activation token %s\n", tokenString)
		default:
			fmt.Printf("Unrecognised token %s\n", tokenString)
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

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
	rw.WriteHeader(http.StatusUnauthorized)
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
		Get("/api/test", (*AuthPlzCtx).Test).
		Get("/api/status", (*AuthPlzCtx).Status)

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
