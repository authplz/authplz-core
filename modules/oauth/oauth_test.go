package oauth

import (
	"log"
	"net/http"
	"net/url"
	"testing"
)

import (
	"github.com/gocraft/web"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/ryankurte/authplz/appcontext"
	"github.com/ryankurte/authplz/controllers/datastore"
	"github.com/ryankurte/authplz/controllers/token"
	"github.com/ryankurte/authplz/modules/core"
	"github.com/ryankurte/authplz/modules/user"
	"github.com/ryankurte/authplz/test"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
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

	// Create router with base context
	router := web.New(appcontext.AuthPlzCtx{}).
		Middleware(appcontext.BindContext(&ac)).
		Middleware((*appcontext.AuthPlzCtx).SessionMiddleware)

	//router.Middleware(api.BindContext(&server.ctx))

	//ocs := OauthClientStore{}

	// Fake storage backend for oauth creds
	store := NewTestingStorage()

	// Create oauth server instance
	oauthModule, _ := NewController(store)

	coreModule.BindAPI(router)
	oauthModule.BindAPI(router)
	userModule.BindAPI(router)

	address := "localhost:9000"

	uuid := "fakeUuid"
	redirect := "localhost:9000/auth"

	var oauthClient *OauthClient = nil

	handler := context.ClearHandler(router)
	go func() {
		err := http.ListenAndServe(address, handler)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
		t.FailNow()
	}()

	client := test.NewTestClient("http://" + address + "/api")
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
	t.Run("OAuth check API is bound", func(t *testing.T) {
		client.BindTest(t).TestGet("/oauth/test", http.StatusOK)
	})

	t.Run("OAuth enrol non-interactive client", func(t *testing.T) {
		c, err := oauthModule.CreateClient(uuid, "scopeA", redirect)
		if err != nil {
			t.Error(err)
		}
		oauthClient = c
	})

	t.Run("OAuth list clients", func(t *testing.T) {
		c, err := oauthModule.GetClients(uuid)
		if err != nil {
			t.Error(err)
		}
		log.Printf("%+v\n", c)
	})

	t.Run("OAuth login as non-interactive client", func(t *testing.T) {
		config := &clientcredentials.Config{
			ClientID:     oauthClient.ClientId,
			ClientSecret: oauthClient.Secret,
			TokenURL:     "http://" + address + "/api/oauth/token"}

		httpClient := config.Client(oauth2.NoContext)

		tc := test.NewTestClientFromHttp("http://"+address+"/api/oauth", httpClient)

		tc.BindTest(t).TestGet("/info", http.StatusOK)
	})

	t.Run("OAuth can remove non-interactive clients", func(t *testing.T) {
		err := oauthModule.RemoveClient(oauthClient.ClientId)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Removing non-interactive client causes OAuth to fail", func(t *testing.T) {
		config := &clientcredentials.Config{
			ClientID:     oauthClient.ClientId,
			ClientSecret: oauthClient.Secret,
			TokenURL:     "http://" + address + "/api/oauth/token"}

		httpClient := config.Client(oauth2.NoContext)

		tc := test.NewTestClientFromHttp("http://"+address+"/api/oauth", httpClient)

		var oauthError OauthError
		tc.BindTest(t).TestGet("/info", http.StatusOK).TestParseJson(&oauthError)
		if oauthError.Error == "" {
			t.Errorf("Expected error response")
		}
	})

	t.Run("OAuth users can register interactive clients", func(t *testing.T) {
		t.Skipf("Unimplemented")
	})

	t.Run("Interactive clients can login with OAuth", func(t *testing.T) {
		t.Skipf("Unimplemented")
	})

}
