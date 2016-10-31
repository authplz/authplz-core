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
    ds      *datastore.DataStore
    ctx     AuthPlzGlobalCtx
    router  *web.Router
}

func NewServer(config AuthPlzConfig) *AuthPlzServer {
    server := AuthPlzServer{}

    server.address = config.Address
    server.port = config.Port

    gob.Register(&token.TokenClaims{})
    gob.Register(&u2f.Challenge{})

    // Attempt database connection
    ds, err := datastore.NewDataStore(config.Database)
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
    server.ctx = AuthPlzGlobalCtx{server.port, server.address, &uc, &tc, sessionStore}

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
