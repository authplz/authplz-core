package test

import (
	"log"
	"net/http"

	"github.com/gocraft/web"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/ryankurte/authplz/appcontext"
	"github.com/ryankurte/authplz/controllers/datastore"
	"github.com/ryankurte/authplz/controllers/token"
	"github.com/ryankurte/authplz/modules/core"
	"github.com/ryankurte/authplz/modules/user"
)

const (
	Address   = "localhost:9000"
	FakeEmail = "test@abc.com"
	FakePass  = "abcDEF123@9c"
	FakeName  = "user.sdfsfdF"
	DBString  = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"
)

type TestServer struct {
	Router       *web.Router
	DataStore    *datastore.DataStore
	CoreModule   *core.Controller
	EventEmitter *MockEventEmitter
}

func NewTestServer() (*TestServer, error) {
	ds, err := datastore.NewDataStore(DBString)
	if err != nil {
		return nil, err
	}
	ds.ForceSync()

	sessionStore := sessions.NewCookieStore([]byte("abcDEF123"))
	ac := appcontext.AuthPlzGlobalCtx{
		SessionStore: sessionStore,
	}

	tokenControl := token.NewTokenController("localhost", "abcDEF123")

	mockEventEmitter := MockEventEmitter{}
	userModule := user.NewController(ds, &mockEventEmitter)

	coreModule := core.NewController(tokenControl, userModule)
	coreModule.BindModule("user", userModule)

	// Create router with base context
	router := web.New(appcontext.AuthPlzCtx{}).
		Middleware(appcontext.BindContext(&ac)).
		Middleware((*appcontext.AuthPlzCtx).SessionMiddleware)

	coreModule.BindAPI(router)
	userModule.BindAPI(router)

	return &TestServer{router, ds, coreModule, &mockEventEmitter}, nil
}

func (ts *TestServer) Run() {

	handler := context.ClearHandler(ts.Router)
	go func() {
		err := http.ListenAndServe(Address, handler)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}()

}
