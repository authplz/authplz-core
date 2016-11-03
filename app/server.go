package app

import "os"

//import "strings"
import "log"
import "path"
import "net/http"

import "encoding/gob"
import "encoding/base64"

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
		log.Panic("Error opening database")
	}
	server.ds = ds

	// Create session store
	cookieSecret, err := base64.URLEncoding.DecodeString(config.CookieSecret)
	if err != nil {
		log.Println(err)
		log.Panic("Error decoding cookie secret")
	}
	//log.Printf("Cookie secret: %s\n", CookieSecret)
	sessionStore := sessions.NewCookieStore(cookieSecret)

	// TODO: Create CSRF middleware

	// Create controllers
	uc := usercontroller.NewUserController(server.ds, server.ds, nil)

	tokenSecret, err := base64.URLEncoding.DecodeString(config.TokenSecret)
	if err != nil {
		log.Println(err)
		log.Panic("Error decoding token secret")
	}
	//log.Printf("Token secret: %s\n", TokenSecret)
	tc := token.NewTokenController(server.config.Address, string(tokenSecret))

	// Create a global context object
	server.ctx = AuthPlzGlobalCtx{config.Port, config.Address, &uc, &tc, sessionStore}

	// Create router
	server.router = web.New(AuthPlzCtx{}).
		Middleware(BindContext(&server.ctx)).
		//Middleware(web.LoggerMiddleware).
		//Middleware(web.ShowErrorsMiddleware).
		Middleware((*AuthPlzCtx).SessionMiddleware).
        Middleware((*AuthPlzCtx).GetIPMiddleware)

	// Enable static file hosting
	_, _ = os.Getwd()
	staticPath := path.Clean(config.StaticDir)
	log.Printf("Loading static content from: %s\n", staticPath)
	server.router.Middleware(web.StaticMiddleware(staticPath, web.StaticOption{IndexFile: "index.html"}))

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
    apiRouter.Get("/u2f/tokens", (*AuthPlzCtx).U2FTokensGet)

	return &server
}

func (server *AuthPlzServer) Start() {
	// Start listening

	// Set bind address
	address := server.config.Address + ":" + server.config.Port
	

	// Create GoCraft handler
	handler := context.ClearHandler(server.router)

	// Start with/without TLS
	var err error
	if server.config.NoTls == true {
		log.Println("*******************************************************************************")
		log.Println("WARNING: TLS IS DISABLED. USE FOR TESTING OR WITH EXTERNAL TLS TERMINATION ONLY")
		log.Println("*******************************************************************************")
		log.Printf("Listening at: http://%s", address)
		err = http.ListenAndServe(address, handler)
	} else {
		log.Printf("Listening at: https://%s", address)
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
