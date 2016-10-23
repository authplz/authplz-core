package logcontroller

import "testing"

import "github.com/ryankurte/authplz/datastore"

func TestLogController(t *testing.T) {
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
	lc := NewLogController(ds)

	// Create fake user
	u, _ := ds.AddUser(fakeEmail, fakePass)

	// Run tests
	t.Run("Add login event", func(t *testing.T) {
		err := lc.AddEvent(u, LoginEvent)
		if err != nil {
			t.Error(err)
			return
		}
	})

	// Tear down user controller

}
