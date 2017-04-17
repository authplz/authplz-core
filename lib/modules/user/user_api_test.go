package user

import (
	"log"
	"net/http"
	"testing"
)

import (
	"github.com/gocraft/web"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"

	"github.com/ryankurte/authplz/lib/api"
	"github.com/ryankurte/authplz/lib/appcontext"
	"github.com/ryankurte/authplz/lib/config"
	"github.com/ryankurte/authplz/lib/controllers/datastore"
	"github.com/ryankurte/authplz/lib/test"
)

func TestUserApi(t *testing.T) {
	// Setup user controller for testing
	var address = "localhost:8811"

	c, _ := config.DefaultConfig()

	// Attempt database connection
	dataStore, err := datastore.NewDataStore(c.Database)
	if err != nil {
		t.Error("Error opening database")
		t.FailNow()
	}
	dataStore.ForceSync()

	// Create controllers
	sessionStore := sessions.NewCookieStore([]byte("abcDEF123"))
	mockEventEmitter := test.MockEventEmitter{}
	userModule := NewController(dataStore, &mockEventEmitter)

	ac := appcontext.AuthPlzGlobalCtx{
		SessionStore: sessionStore,
	}

	router := web.New(appcontext.AuthPlzCtx{}).
		Middleware(appcontext.BindContext(&ac)).
		//Middleware(web.LoggerMiddleware).
		//Middleware(web.ShowErrorsMiddleware).
		Middleware((*appcontext.AuthPlzCtx).SessionMiddleware).
		Middleware((*appcontext.AuthPlzCtx).GetIPMiddleware).
		Middleware((*appcontext.AuthPlzCtx).GetLocaleMiddleware)

	userModule.BindAPI(router)

	handler := context.ClearHandler(router)

	go func() {
		err = http.ListenAndServe(address, handler)
		if err != nil {
			log.Panic(err)
		}
	}()

	// Setup test helpers
	client := test.NewTestClient("http://" + address + "/api")

	// Run tests
	t.Run("Login status", func(t *testing.T) {
		if err := client.GetAPIResponse("/status", http.StatusOK, api.ResultError, api.GetApiLocale(api.DefaultLocale).Unauthorized); err != nil {
			t.Error(err)
		}
	})

	// TODO: move user api tests here

}
