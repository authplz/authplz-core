package main

import "os"

//import "strings"
import "fmt"
import "log"
import "net/http"

//import "encoding/json"

import "github.com/gocraft/web"

//import "github.com/kataras/iris"
import "github.com/gorilla/sessions"
import "github.com/gorilla/context"

import "github.com/asaskevich/govalidator"

import "github.com/ryankurte/authplz/usercontroller"
import "github.com/ryankurte/authplz/datastore"

// Application context
// TODO: this could be split and bound by module
type AuthPlzCtx struct {
	port           string
	address        string
	userController *usercontroller.UserController
	sessionStore   *sessions.CookieStore
}

// User session layer
func (ctx *AuthPlzCtx) SessionMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	fmt.Println(ctx)
	session, err := ctx.sessionStore.Get(req.Request, "user-session")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(session)
	}

	//session.Save(r, w)
	next(rw, req)
}

// Convenience type to describe middleware functions
type MiddlewareFunc func(ctx *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc)

const internalServerError string = "Internal Server Error"

// Bind global context into the router
func BindContext(extCtx AuthPlzCtx) MiddlewareFunc {
	return func(ctx *AuthPlzCtx, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		// Bind global components to context
		ctx.port = extCtx.port
		ctx.address = extCtx.address
		ctx.userController = extCtx.userController
		ctx.sessionStore = extCtx.sessionStore

		next(rw, req)
	}
}

// Create a user
func (c *AuthPlzCtx) Create(rw web.ResponseWriter, req *web.Request) {
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		fmt.Fprint(rw, "email parameter required")
		return
	}
	password := req.FormValue("password")
	if password == "" {
		fmt.Fprint(rw, "password parameter required")
		return
	}

	u, e := c.userController.Create(email, password)
	if e != nil {
		fmt.Fprint(rw, "Error: %s", e)
		rw.WriteHeader(500)
	}

	if u == nil {
		rw.WriteHeader(503)
	}

	log.Println("Login OK")

	rw.WriteHeader(501)
}

// Login to a user account
func (c *AuthPlzCtx) Login(rw web.ResponseWriter, req *web.Request) {
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		fmt.Fprint(rw, "email parameter required")
		return
	}
	password := req.FormValue("password")
	if password == "" {
		fmt.Fprint(rw, "password parameter required")
		return
	}

	u, e := c.userController.Login(email, password)
	if e != nil {
		fmt.Fprint(rw, "Error: %s", e)
		rw.WriteHeader(500)
	}

	if u == nil {
		rw.WriteHeader(503)
	}

	log.Println("Login OK")

	rw.WriteHeader(200)
}

// Logout of a user account
func (c *AuthPlzCtx) Logout(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(501)
}

// Get user login status
func (c *AuthPlzCtx) Status(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(http.StatusUnauthorized)
}

type AuthPlzServer struct {
	address string
	port    string
	ds      datastore.DataStore
	ctx     AuthPlzCtx
	router  *web.Router
}

func NewServer(address string, port string, db string) *AuthPlzServer {
	server := AuthPlzServer{}

	server.address = address
	server.port = port

	// Attempt database connection
	server.ds = datastore.NewDataStore(db)

	// Create session store
	sessionStore := sessions.NewCookieStore([]byte("something-very-secret"))

	// Create controllers
	uc := usercontroller.NewUserController(&(server.ds), nil)

	// Create a global context object
	server.ctx = AuthPlzCtx{port, address, &uc, sessionStore}

	// Create router
	server.router = web.New(AuthPlzCtx{}).
		Middleware(BindContext(server.ctx)).
		Middleware(web.LoggerMiddleware).
		Middleware(web.ShowErrorsMiddleware).
		Middleware((*AuthPlzCtx).SessionMiddleware).
		Post("/api/login", (*AuthPlzCtx).Login).
		Post("/api/create", (*AuthPlzCtx).Create).
		Get("/api/logout", (*AuthPlzCtx).Logout).
		Get("/api/status", (*AuthPlzCtx).Status)

	// Start listening
	fmt.Println("Listening at: " + port)

	return &server
}

func (server *AuthPlzServer) Start() {
	http.ListenAndServe(server.address+":"+server.port, context.ClearHandler(server.router))
}

func (server *AuthPlzServer) Close() {
	server.ds.Close()
}

func main() {
	var port string = "9000"
	var address string = "loalhost"
	var dbString string = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Parse environmental variables
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}

	NewServer(address, port, dbString)

}
