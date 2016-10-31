package main

import "os"

//import "strings"
import "log"
import "path"
import "net/http"

import "encoding/gob"

import "github.com/gocraft/web"

//import "github.com/kataras/iris"
import "github.com/gorilla/sessions"
import "github.com/gorilla/context"

//import "github.com/gorilla/csrf"
import "github.com/ryankurte/go-u2f"

import "github.com/ryankurte/authplz/usercontroller"
import "github.com/ryankurte/authplz/token"
import "github.com/ryankurte/authplz/datastore"
import "github.com/ryankurte/authplz/api"

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
	message string
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
		next(rw, req)
		return
	}

	// Save session for further use
	ctx.session = session

	// Load user from session if set
	// TODO: this will be replaced with sessions when implemented
	if session.Values["userId"] != nil {
		//TODO: find user account
		ctx.userid = session.Values["userId"].(string)
	}

	session.Save(req.Request, rw)
	next(rw, req)
}

func (c *AuthPlzCtx) RequireAccountMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	if c.userid == "" {
		c.WriteApiResult(rw, api.ApiResultError, "You must be signed in to view this page")
	} else {
		next(rw, req)
	}
}

func (c *AuthPlzCtx) LoginUser(u *datastore.User, rw web.ResponseWriter, req *web.Request) {
	c.session.Values["userId"] = u.ExtId
	c.session.Save(req.Request, rw)
	c.userid = u.ExtId
}

func (c *AuthPlzCtx) LogoutUser(rw web.ResponseWriter, req *web.Request) {
	c.session.Options.MaxAge = -1
	c.session.Save(req.Request, rw)
	c.userid = ""
}

func (c *AuthPlzCtx) SetFlashMessage(message string, rw web.ResponseWriter, req *web.Request) {
	session, err := c.global.sessionStore.Get(req.Request, "user-message")
	if err != nil {
		return
	}
	session.AddFlash(message)

	c.session.Save(req.Request, rw)
}

func (c *AuthPlzCtx) GetFlashMessage(rw web.ResponseWriter, req *web.Request) string {
	session, err := c.global.sessionStore.Get(req.Request, "user-message")
	if err != nil {
		return ""
	}

	flashes := session.Flashes()
	if len(flashes) > 0 {
		return flashes[0].(string)
	}

	return ""
}

type AuthPlzServer struct {
	address string
	port    string
	ds      *datastore.DataStore
	ctx     AuthPlzGlobalCtx
	router  *web.Router
}

type AuthPlzConfig struct {
	Address      string
	Port         string
	Database     string
	CookieSecret string
	TokenSecret  string
}

func NewServer(address string, port string, db string) *AuthPlzServer {
	server := AuthPlzServer{}

	server.address = address
	server.port = port

	gob.Register(&token.TokenClaims{})
	gob.Register(&u2f.Challenge{})

	// Attempt database connection
	ds, err := datastore.NewDataStore(db)
	if err != nil {
		panic("Error opening database")
	}
	server.ds = ds

	// Create session store
	sessionStore := sessions.NewCookieStore([]byte("something-very-secret"))

	// TODO: Create CSRF middleware

	// Create controllers
	uc := usercontroller.NewUserController(server.ds, server.ds, nil)
	tc := token.NewTokenController(server.address, "something-also-secret")

	// Create a global context object
	server.ctx = AuthPlzGlobalCtx{port, address, &uc, &tc, sessionStore}

	// Create router
	server.router = web.New(AuthPlzCtx{}).
		Middleware(BindContext(&server.ctx)).
		//Middleware(web.LoggerMiddleware).
		//Middleware(web.ShowErrorsMiddleware).
		Middleware((*AuthPlzCtx).SessionMiddleware)

	// Enable static file hosting
	currentRoot, _ := os.Getwd()
	server.router.Middleware(web.StaticMiddleware(path.Join(currentRoot, "static"), web.StaticOption{IndexFile: "index.html"}))

	// Create API router
	// TODO: this can probably be a separate module, but would require AuthPlzCtx/AuthPlzGlobalCtx to be in a package
	apiRouter := server.router.Subrouter(AuthPlzCtx{}, "/api")

	apiRouter.Post("/create", (*AuthPlzCtx).Create)
	apiRouter.Post("/login", (*AuthPlzCtx).Login)
	apiRouter.Post("/action", (*AuthPlzCtx).Action)
	apiRouter.Get("/action", (*AuthPlzCtx).Action)
	apiRouter.Get("/logout", (*AuthPlzCtx).Logout)
	apiRouter.Get("/status", (*AuthPlzCtx).Status)
	apiRouter.Get("/account", (*AuthPlzCtx).Account)
	apiRouter.Get("/test", (*AuthPlzCtx).Test)

	apiRouter.Get("/u2f/enrol", (*AuthPlzCtx).U2FEnrolGet)
	apiRouter.Post("/u2f/enrol", (*AuthPlzCtx).U2FEnrolPost)
	apiRouter.Get("/u2f/authenticate", (*AuthPlzCtx).U2FAuthenticateGet)
	apiRouter.Post("/u2f/authenticate", (*AuthPlzCtx).U2FAuthenticatePost)

	return &server
}

func (server *AuthPlzServer) Start() {
	// Start listening
	log.Println("Listening at: " + server.port)
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
