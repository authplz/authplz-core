package oauth

import "testing"

//import "fmt"

import (
	"crypto/rand"
	"crypto/rsa"
)

import (
	"github.com/ryankurte/authplz/controllers/datastore"
	//"golang.org/x/oauth2"
	//"golang.org/x/oauth2/clientcredentials"
)

type OauthError struct {
	Error            string
	ErrorDescription string
}

func TestMain(t *testing.T) {
	// Setup user controller for testing
	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@"
	var fakeName = "user.sdfsfdF"
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Attempt database connection

	ds, err := datastore.NewDataStore(dbString)
	if err != nil {
		t.Error("Error opening database")
		t.FailNow()
	}
	ds.ForceSync()

	// Create fake user
	u, _ := ds.AddUser(fakeEmail, fakeName, fakePass)
	user := u.(*datastore.User)

	// Create oauth server instance
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	oc, _ := NewController(Config{key}, ds)

	//var oauthClient *OauthClient

	// Run tests
	t.Run("Fake Test", func(t *testing.T) {
		oc.Fake()
		user.IsActivated()
	})

}
