/*
 * Test Helpers
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package test

import (
	"fmt"
	"log"
	"math/rand"
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
	FakeEmail = "test@abc.com"
	FakePass  = "abcDEF123@9c"
	FakeName  = "user.sdfsfdF"
)

type TestServer struct {
	Router       *web.Router
	DataStore    *datastore.DataStore
	TokenControl *token.TokenController
	EventEmitter *MockEventEmitter
	Config       *config.AuthPlzConfig
}

func NewTestServer() (*TestServer, error) {
	c := NewConfig()

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

	return &TestServer{router, ds, tokenControl, &mockEventEmitter, c}, nil
}

func (ts *TestServer) Address() string {
	return fmt.Sprintf("%s:%s", ts.Config.Address, ts.Config.Port)
}

func (ts *TestServer) Run() {

	handler := context.ClearHandler(ts.Router)
	go func() {
		err := http.ListenAndServe(ts.Address(), handler)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}()
}

// NewConfig generates a test configuration
func NewConfig() *config.AuthPlzConfig {
	c, _ := config.DefaultConfig()

	c.Port = fmt.Sprintf("%d", rand.Uint32()%10000+10000)

	c.TLS.Disabled = true
	c.ExternalAddress = fmt.Sprintf("http://%s:%s", c.Address, c.Port)
	c.AllowedOrigins = []string{c.ExternalAddress, "https://authplz.herokuapp.com"}
	c.TemplateDir = "../../templates"
	c.Mailer.Driver = "logger"
	c.Mailer.Options = map[string]string{"mode": "silent"}
	c.DisableWebSecurity = true

	return c
}
