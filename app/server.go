package app

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

type AuthPlzServer struct {
	address string
	port    string
	config  AuthPlzConfig
	ds      *datastore.DataStore
	ctx     AuthPlzGlobalCtx
	router  *web.Router
}

func NewServer(config AuthPlzConfig) *AuthPlzServer {
	server := AuthPlzServer{}

	server.config = config

	gob.Register(&token.TokenClaims{})
	gob.Register(&u2f.Challenge{})

	// Attempt database connection
	ds, err := datastore.NewDataStore(config.Database)
	if err != nil {
		panic("Error opening database")
	}
	server.ds = ds

	// Create session store
	sessionStore := sessions.NewCookieStore([]byte(config.CookieSecret))

	// TODO: Create CSRF middleware

	// Create controllers
	uc := usercontroller.NewUserController(server.ds, server.ds, nil)
	tc := token.NewTokenController(server.config.Address, config.TokenSecret)

	// Create a global context object
	server.ctx = AuthPlzGlobalCtx{config.Port, config.Address, &uc, &tc, sessionStore}

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
	apiRouter.Get("/account", (*AuthPlzCtx).AccountGet)
	apiRouter.Post("/account", (*AuthPlzCtx).AccountPost)
	apiRouter.Get("/test", (*AuthPlzCtx).Test)

	apiRouter.Get("/u2f/enrol", (*AuthPlzCtx).U2FEnrolGet)
	apiRouter.Post("/u2f/enrol", (*AuthPlzCtx).U2FEnrolPost)
	apiRouter.Get("/u2f/authenticate", (*AuthPlzCtx).U2FAuthenticateGet)
	apiRouter.Post("/u2f/authenticate", (*AuthPlzCtx).U2FAuthenticatePost)
    apiRouter.Get("/u2f/status", (*AuthPlzCtx).U2FStatusGet)

	return &server
}

func (server *AuthPlzServer) Start() {
	// Start listening

	// Set bind address
	address := server.config.Address + ":" + server.config.Port
	log.Printf("Listening at: %s", address)

	// Create GoCraft handler
	handler := context.ClearHandler(server.router)

	// Start with/without TLS
	var err error
	if server.config.NoTls == true {
		log.Println("*******************************************************************************")
		log.Println("WARNING: TLS IS DISABLED. USE FOR TESTING OR WITH EXTERNAL TLS TERMINATION ONLY")
		log.Println("*******************************************************************************")
		err = http.ListenAndServe(address, handler)
	} else {
		err = http.ListenAndServeTLS(address, server.config.TlsCert, server.config.TlsKey, handler)
	}

	// Handle errors
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func (server *AuthPlzServer) Close() {
	server.ds.Close()
}
