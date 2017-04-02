package app

import (
	"log"
	"net/http"
	"os"
	"path"
)

import (
	"github.com/gocraft/web"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"

	"github.com/ryankurte/authplz/lib/api"
	"github.com/ryankurte/authplz/lib/appcontext"
	"github.com/ryankurte/authplz/lib/config"

	"github.com/ryankurte/authplz/lib/controllers/datastore"
	"github.com/ryankurte/authplz/lib/controllers/token"

	"github.com/ryankurte/authplz/lib/modules/2fa/backup"
	"github.com/ryankurte/authplz/lib/modules/2fa/totp"
	"github.com/ryankurte/authplz/lib/modules/2fa/u2f"

	"github.com/ryankurte/authplz/lib/modules/audit"
	"github.com/ryankurte/authplz/lib/modules/core"
	"github.com/ryankurte/authplz/lib/modules/user"

	"github.com/ryankurte/go-async"
)

// AuthPlzServer Base AuthPlz server object
type AuthPlzServer struct {
	address        string
	port           string
	config         config.AuthPlzConfig
	ds             *datastore.DataStore
	ctx            appcontext.AuthPlzGlobalCtx
	router         *web.Router
	tokenControl   *token.TokenController
	serviceManager *async.ServiceManager
}

const bufferSize uint = 64

// NewServer Create an AuthPlz server instance
func NewServer(config config.AuthPlzConfig) *AuthPlzServer {
	server := AuthPlzServer{}

	server.config = config

	// Attempt database connection
	dataStore, err := datastore.NewDataStore(config.Database)
	if err != nil {
		log.Panic("Error opening database")
	}
	server.ds = dataStore

	// Create session store
	sessionStore := sessions.NewCookieStore([]byte(config.CookieSecret))

	// Create token controller
	tokenControl := token.NewTokenController(server.config.Address, string(config.TokenSecret))
	server.tokenControl = tokenControl

	// TODO: Create CSRF middleware

	// Create modules

	// Create service manager
	server.serviceManager = async.NewServiceManager(bufferSize)

	// User management module
	userModule := user.NewController(dataStore, server.serviceManager)

	// Core module
	coreModule := core.NewController(tokenControl, userModule)

	coreModule.BindModule("user", userModule)
	coreModule.BindActionHandler(api.TokenActionActivate, userModule)
	coreModule.BindActionHandler(api.TokenActionUnlock, userModule)

	// U2F module
	u2fModule := u2f.NewController(config.Address, dataStore, server.serviceManager)
	coreModule.BindSecondFactor("u2f", u2fModule)

	totpModule := totp.NewController(config.Name, dataStore, server.serviceManager)
	coreModule.BindSecondFactor("totp", totpModule)

	backupModule := backup.NewController(config.Name, dataStore, server.serviceManager)
	coreModule.BindSecondFactor("backup", backupModule)

	// Audit module (async components)
	auditModule := audit.NewController(dataStore)
	auditSvc := async.NewAsyncService(auditModule, bufferSize)
	server.serviceManager.BindService(&auditSvc)

	// Create a global context object
	server.ctx = appcontext.NewGlobalCtx(sessionStore)

	// Create router
	server.router = web.New(appcontext.AuthPlzCtx{}).
		Middleware(appcontext.BindContext(&server.ctx)).
		Middleware(web.LoggerMiddleware).
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
	u2fModule.BindAPI(server.router)
	totpModule.BindAPI(server.router)
	backupModule.BindAPI(server.router)
	auditModule.BindAPI(server.router)

	return &server
}

// Start an instance of the AuthPlzServer
func (server *AuthPlzServer) Start() {
	// Start listening

	// Set bind address
	address := server.config.Address + ":" + server.config.Port

	// Create GoCraft handler
	handler := context.ClearHandler(server.router)

	// Start async services
	server.serviceManager.Run()

	// Start with/without TLS
	var err error
	if server.config.NoTLS == true {
		log.Println("*******************************************************************************")
		log.Println("WARNING: TLS IS DISABLED. USE FOR TESTING OR WITH EXTERNAL TLS TERMINATION ONLY")
		log.Println("*******************************************************************************")
		log.Printf("Listening at: http://%s", address)
		err = http.ListenAndServe(address, handler)
	} else {
		log.Printf("Listening at: https://%s", address)
		err = http.ListenAndServeTLS(address, server.config.TLSCert, server.config.TLSKey, handler)
	}

	// Stop async services
	server.serviceManager.Exit()

	// Handle errors
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

// Close an instance of the AuthPlzServer
func (server *AuthPlzServer) Close() {
	// TODO: stop HTTP server

	// Stop workers
	server.serviceManager.Exit()

	// Close datastore
	server.ds.Close()
}
