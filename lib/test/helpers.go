package test

import (
	"log"
	"net/http"

	"github.com/gocraft/web"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"

	"github.com/authplz/authplz-core/lib/appcontext"
	"github.com/authplz/authplz-core/lib/config"
	"github.com/authplz/authplz-core/lib/controllers/datastore"
	"github.com/authplz/authplz-core/lib/controllers/token"
)

const (
	Address   = "localhost:9000"
	FakeEmail = "test@abc.com"
	FakePass  = "abcDEF123@9c"
	FakeName  = "user.sdfsfdF"
)

type TestServer struct {
	Router       *web.Router
	DataStore    *datastore.DataStore
	TokenControl *token.TokenController
	EventEmitter *MockEventEmitter
}

func NewTestServer() (*TestServer, error) {
	c, _ := config.DefaultConfig()

	ds, err := datastore.NewDataStore(c.Database)
	if err != nil {
		return nil, err
	}
	ds.ForceSync()

	sessionStore := sessions.NewCookieStore([]byte("abcDEF123"))
	ac := appcontext.AuthPlzGlobalCtx{
		SessionStore: sessionStore,
	}

	tokenControl := token.NewTokenController("localhost", "abcDEF123", ds)

	mockEventEmitter := MockEventEmitter{}

	// Create router with base context
	router := web.New(appcontext.AuthPlzCtx{}).
		Middleware(appcontext.BindContext(&ac)).
		Middleware((*appcontext.AuthPlzCtx).SessionMiddleware)

	return &TestServer{router, ds, tokenControl, &mockEventEmitter}, nil
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
