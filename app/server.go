package app

import (
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"path"
)

import (
	"github.com/gocraft/web"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"

	"github.com/ryankurte/authplz/api"
	"github.com/ryankurte/authplz/appcontext"

	"github.com/ryankurte/authplz/controllers/datastore"
	"github.com/ryankurte/authplz/controllers/token"
	"github.com/ryankurte/authplz/modules/core"
	"github.com/ryankurte/authplz/modules/user"
)

// Base AuthPlz server object
type AuthPlzServer struct {
	address string
	port    string
	config  AuthPlzConfig
	ds      *datastore.DataStore
	ctx     appcontext.AuthPlzGlobalCtx
	router  *web.Router
	tokenControl *token.TokenController
}

// Create an AuthPlz server instance
func NewServer(config AuthPlzConfig) *AuthPlzServer {
	server := AuthPlzServer{}

	server.config = config

	// Attempt database connection
	dataStore, err := datastore.NewDataStore(config.Database)
	if err != nil {
		log.Panic("Error opening database")
	}
	server.ds = dataStore

	// Parse secrets
	cookieSecret, err := base64.URLEncoding.DecodeString(config.CookieSecret)
	if err != nil {
		log.Println(err)
		log.Panic("Error decoding cookie secret")
	}

	// Create session store
	sessionStore := sessions.NewCookieStore(cookieSecret)

	// TODO: Create CSRF middleware

	// Create shared controllers

	// Create token controller
	tokenSecret, err := base64.URLEncoding.DecodeString(config.TokenSecret)
	if err != nil {
		log.Println(err)
		log.Panic("Error decoding cookie secret")
	}
	tokenControl := token.NewTokenController(server.config.Address, string(tokenSecret))
	server.tokenControl = tokenControl

	// Create modules

	// User management module
	userModule := user.NewUserModule(dataStore)

	// Core module
	coreModule := core.NewCoreModule(tokenControl, userModule)
	coreModule.BindActionHandler(api.TokenActionActivate, userModule)
	coreModule.BindActionHandler(api.TokenActionUnlock, userModule)

	// Generate URL string
	var url string
	if config.NoTls == false {
		url = "https://" + config.Address + ":" + config.Port
	} else {
		url = "http://" + config.Address + ":" + config.Port
	}

	// Create a global context object
	server.ctx = appcontext.NewGlobalCtx(config.Port, config.Address, url, sessionStore)

	// Create router
	server.router = web.New(appcontext.AuthPlzCtx{}).
		Middleware(appcontext.BindContext(&server.ctx)).
		//Middleware(web.LoggerMiddleware).
		Middleware((*appcontext.AuthPlzCtx).SessionMiddleware).
		Middleware((*appcontext.AuthPlzCtx).GetIPMiddleware).
		Middleware((*appcontext.AuthPlzCtx).GetLocaleMiddleware)

	// Enable static file hosting
	_, _ = os.Getwd()
	staticPath := path.Clean(config.StaticDir)
	log.Printf("Loading static content from: %s\n", staticPath)
	server.router.Middleware(web.StaticMiddleware(staticPath, web.StaticOption{IndexFile: "index.html"}))

	// Bind modules to router
	coreModule.BindAPI(server.router)
	userModule.BindAPI(server.router)

	/*
		apiRouter.Get("/u2f/enrol", (*AuthPlzTempCtx).U2FEnrolGet)
		apiRouter.Post("/u2f/enrol", (*AuthPlzTempCtx).U2FEnrolPost)
		apiRouter.Get("/u2f/authenticate", (*AuthPlzTempCtx).U2FAuthenticateGet)
		apiRouter.Post("/u2f/authenticate", (*AuthPlzTempCtx).U2FAuthenticatePost)
		apiRouter.Get("/u2f/tokens", (*AuthPlzTempCtx).U2FTokensGet)
	*/
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
