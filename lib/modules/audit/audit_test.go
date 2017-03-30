package audit

import (
	"testing"
	"time"
)

import (
	"github.com/ryankurte/authplz/lib/api"
	"github.com/ryankurte/authplz/lib/controllers/datastore"
	"github.com/ryankurte/go-async"
)

func TestAuditController(t *testing.T) {
	// Setup user controller for testing
	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@"
	var fakeName = "user.sdfsfdF"
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	serviceManager := async.NewServiceManager(64)

	// Attempt database connection
	ds, err := datastore.NewDataStore(dbString)
	if err != nil {
		t.Error("Error opening database")
		t.FailNow()
	}
	ds.ForceSync()

	// Create controllers
	ac := NewController(ds)
	auditSvc := async.NewAsyncService(ac, 64)
	serviceManager.BindService(&auditSvc)

	// Create fake user
	u, _ := ds.AddUser(fakeEmail, fakeName, fakePass)
	user := u.(*datastore.User)

	// Run tests
	t.Run("Add login event", func(t *testing.T) {
		err := ac.AddEvent(user, api.EventAccountCreated, time.Now(), make(map[string]string))
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Can list events", func(t *testing.T) {
		events, err := ac.ListEvents(user.GetExtID())
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
		events, err := ac.ListEvents(user.GetExtID())
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
