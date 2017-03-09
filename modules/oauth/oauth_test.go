package oauth

import "testing"

//import "fmt"

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"net/url"
)

import (
	"github.com/gocraft/web"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	//"github.com/ryankurte/authplz/api"
	"github.com/ryankurte/authplz/appcontext"
	"github.com/ryankurte/authplz/controllers/datastore"
	"github.com/ryankurte/authplz/controllers/token"
	"github.com/ryankurte/authplz/modules/core"
	"github.com/ryankurte/authplz/modules/user"
	"github.com/ryankurte/authplz/test"
	//"golang.org/x/oauth2"
	//"golang.org/x/oauth2/clientcredentials"
	"github.com/ory-am/fosite/storage"
)

type OauthError struct {
	Error            string
	ErrorDescription string
}

func TestMain(t *testing.T) {

	// Setup user controller for testing
	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@9c"
	var fakeName = "user.sdfsfdF"
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Attempt database connection

	ds, err := datastore.NewDataStore(dbString)
	if err != nil {
		t.Error("Error opening database")
		t.FailNow()
	}
	ds.ForceSync()

	sessionStore := sessions.NewCookieStore([]byte("abcDEF123"))
	ac := appcontext.AuthPlzGlobalCtx{
		SessionStore: sessionStore,
	}

	tokenControl := token.NewTokenController("localhost", "abcDEF123")

	mockEventEmitter := test.MockEventEmitter{}
	userModule := user.NewController(ds, &mockEventEmitter)

	coreModule := core.NewController(tokenControl, userModule)
	coreModule.BindModule("user", userModule)

	s := storage.NewMemoryStore()

	// Create oauth server instance
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	oc, _ := NewController(Config{key}, s)

	// Create router with base context
	router := web.New(appcontext.AuthPlzCtx{}).
		Middleware(appcontext.BindContext(&ac)).
		Middleware((*appcontext.AuthPlzCtx).SessionMiddleware)

	coreModule.BindAPI(router)
	oc.BindAPI(router)
	userModule.BindAPI(router)

	address := "localhost:9000"

	//uuid := "fakeUuid"
	redirect := "localhost:9000/auth"

	//var oauthClient *OauthClient

	handler := context.ClearHandler(router)
	go func() {
		err := http.ListenAndServe(address, handler)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
		t.FailNow()
	}()

	client := test.NewTestClient("http://" + address + "/api")

	//var oauthClient *OauthClient
	var userID string

	t.Run("Create User", func(t *testing.T) {

		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		v.Set("username", fakeName)

		client.BindTest(t).TestPostForm("/create", http.StatusOK, v)

		u, _ := ds.GetUserByEmail(fakeEmail)

		user := u.(*datastore.User)
		user.SetActivated(true)
		ds.UpdateUser(user)

		userID = user.GetExtID()
	})

	t.Run("Login user", func(t *testing.T) {

		// Attempt login
		v := url.Values{}
		v.Set("email", fakeEmail)
		v.Set("password", fakePass)
		client.BindTest(t).TestPostForm("/login", http.StatusOK, v)

		// Check user status
		client.TestGet("/status", http.StatusOK)
	})

	// Run tests
	t.Run("OAuth request enrolment", func(t *testing.T) {

		v := url.Values{}
		v.Set("client_id", "testClient")
		v.Set("redirect_uri", redirect)
		v.Set("state", "AAAAAAAAAAAA")
		v.Set("scopes", "scopeA scopeB")

		client.BindTest(t).TestGetWithParams("/oauth/auth", http.StatusOK, v)
	})

}
