package audit

import (
	"testing"
	"time"
)

import (
"github.com/ryankurte/go-async"
	"github.com/ryankurte/authplz/api"
	"github.com/ryankurte/authplz/controllers/datastore"
)

func TestAuditController(t *testing.T) {
	// Setup user controller for testing
	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@"
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	serviceManager := async.NewServiceManager()
	

	// Attempt database connection
	ds, err := datastore.NewDataStore(dbString)
	if err != nil {
		t.Error("Error opening database")
		t.FailNow()
	}
	ds.ForceSync()

	// Create controllers
	ac := NewAuditController(ds)
	auditSvc := async.NewAsyncService(ac)
	serviceManager.BindService(&auditSvc)

	// Create fake user
	u, _ := ds.AddUser(fakeEmail, fakePass)
	user := u.(*datastore.User)

	// Run tests
	t.Run("Add login event", func(t *testing.T) {
		err := ac.AddEvent(user, api.EventAccountCreated, time.Now(), make(map[string]string))
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Can list events", func(t *testing.T) {
		events, err := ac.ListEvents(user.GetExtId())
		if err != nil {
			t.Error(err)
		}
		if len(events) != 1 {
			t.Errorf("Expected 1 event, received %d events", len(events))
		}
	})

	t.Run("Start async server", func(t *testing.T) {
		serviceManager.Run()
	})

	t.Run("Post audit event", func(t *testing.T) {
		d := make(map[string]string)
		d["ip"] = "127.0.0.1"
		e := api.AuthPlzEvent{user, time.Now(), api.EventAccountActivated, d}

		serviceManager.SendEvent(&e)

		time.Sleep(100 * time.Millisecond)
	})

	t.Run("Can list async events", func(t *testing.T) {
		events, err := ac.ListEvents(user.GetExtId())
		if err != nil {
			t.Error(err)
		}
		if len(events) != 2 {
			t.Errorf("Expected 2 events, received %d events", len(events))
		}
	})

	t.Run("Stop async server", func(t *testing.T) {
		serviceManager.Exit()
	})

	// Tear down user controller

}
