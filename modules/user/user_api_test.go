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

	"github.com/ryankurte/authplz/api"
	"github.com/ryankurte/authplz/appcontext"
	"github.com/ryankurte/authplz/controllers/datastore"
	"github.com/ryankurte/authplz/test"
)

func TestUserApi(t *testing.T) {
	// Setup user controller for testing
	//var fakeEmail = "test@abc.com"
	//var fakePass = "abcDEF123@abcDEF123@"
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"
	var address = "localhost:8811"

	// Attempt database connection
	dataStore, err := datastore.NewDataStore(dbString)
	if err != nil {
		t.Error("Error opening database")
		t.FailNow()
	}
	dataStore.ForceSync()

	// Create controllers
	sessionStore := sessions.NewCookieStore([]byte("abcDEF123"))
	mockEventEmitter := test.MockEventEmitter{}
	userModule := NewUserModule(dataStore, &mockEventEmitter)

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
		client.TestGetApiResponse(t, "/status", api.ApiResultError, api.GetApiLocale(api.DefaultLocale).Unauthorized)
	})

	// TODO: move user api tests here

}
