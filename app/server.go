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
	//"github.com/ryankurte/go-u2f"

	"github.com/ryankurte/authplz/appcontext"
	"github.com/ryankurte/authplz/datastore"

	"github.com/ryankurte/authplz/user"
	"github.com/ryankurte/authplz/token"
	//"github.com/ryankurte/authplz/usercontroller"
)

type AuthPlzServer struct {
	address string
	port    string
	config  AuthPlzConfig
	ds      *datastore.DataStore
	ctx     appcontext.AuthPlzGlobalCtx
	router  *web.Router
}

// Temporary mapping between contexts
type AuthPlzTempCtx appcontext.AuthPlzCtx

func NewServer(config AuthPlzConfig) *AuthPlzServer {
	server := AuthPlzServer{}

	server.config = config

	// Attempt database connection
	ds, err := datastore.NewDataStore(config.Database)
	if err != nil {
		log.Panic("Error opening database")
	}
	server.ds = ds

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

	//log.Printf("Token secret: %s\n", TokenSecret)
	tokenSecret, err := base64.URLEncoding.DecodeString(config.TokenSecret)
	if err != nil {
		log.Println(err)
		log.Panic("Error decoding cookie secret")
	}
	tokenController := token.NewTokenController(server.config.Address, string(tokenSecret))

	userModule := user.NewUserModule(ds);

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
	server.router = web.New(AuthPlzTempCtx{}).
		Middleware(appcontext.BindContext(&server.ctx)).
		//Middleware(web.LoggerMiddleware).
		//Middleware(web.ShowErrorsMiddleware).
		Middleware((*appcontext.AuthPlzCtx).SessionMiddleware).
		Middleware((*appcontext.AuthPlzCtx).GetIPMiddleware).
		Middleware((*appcontext.AuthPlzCtx).GetLocaleMiddleware)

	// Enable static file hosting
	_, _ = os.Getwd()
	staticPath := path.Clean(config.StaticDir)
	log.Printf("Loading static content from: %s\n", staticPath)
	server.router.Middleware(web.StaticMiddleware(staticPath, web.StaticOption{IndexFile: "index.html"}))

	// Create API router
	// TODO: this can probably be a separate module, but would require AuthPlzTempCtx/AuthPlzGlobalCtx to be in a package

	userModule.Bind(server.router)


	apiRouter := server.router.Subrouter(AuthPlzTempCtx{}, "/api")
	//apiRouter.Post("/create", (*AuthPlzTempCtx).Create)
	apiRouter.Post("/login", (*AuthPlzTempCtx).Login)
	apiRouter.Post("/action", (*AuthPlzTempCtx).Action)
	apiRouter.Get("/action", (*AuthPlzTempCtx).Action)
	apiRouter.Get("/logout", (*AuthPlzTempCtx).Logout)
	apiRouter.Get("/status", (*AuthPlzTempCtx).Status)
	apiRouter.Get("/account", (*AuthPlzTempCtx).AccountGet)
	apiRouter.Post("/account", (*AuthPlzTempCtx).AccountPost)
	apiRouter.Get("/test", (*AuthPlzTempCtx).Test)
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
