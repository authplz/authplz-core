package audit

import (
	"testing"
	"time"
)

import (
	"github.com/ryankurte/authplz/api"
	"github.com/ryankurte/authplz/controllers/datastore"
)

func TestAuditController(t *testing.T) {
	// Setup user controller for testing
	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@"
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Attempt database connection
	ds, err := datastore.NewDataStore(dbString)
	if err != nil {
		t.Error("Error opening database")
		t.FailNow()
	}
	ds.ForceSync()

	// Create controllers
	ac := NewAuditController(ds)

	// Create fake user
	u, _ := ds.AddUser(fakeEmail, fakePass)
	user := u.(*datastore.User)

	// Run tests
	t.Run("Add login event", func(t *testing.T) {
		err := ac.AddEvent(user, api.EventAccountCreated, time.Now(), make(map[string]string))
		if err != nil {
			t.Error(err)
			return
		}
	})

	// Tear down user controller

}
