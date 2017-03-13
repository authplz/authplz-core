package backup

import (
	"testing"
	//"time"
	"log"
)

import (
	"github.com/ryankurte/authplz/controllers/datastore"
)

func TestBackupModule(t *testing.T) {
	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@abcDEF123@"
	var fakeName = "user.sdfsfdF"
	var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Attempt database connection
	dataStore, err := datastore.NewDataStore(dbString)
	if err != nil {
		t.Error("Error opening database")
		t.FailNow()
	}

	// Force synchronization
	dataStore.ForceSync()

	// Create user for tests
	u, err := dataStore.AddUser(fakeEmail, fakeName, fakePass)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	user := u.(*datastore.User)

	// Create backup controller
	bc := NewController("Test Service", dataStore)

	t.Run("Create backup token", func(t *testing.T) {
		code, err := bc.generateCode(recoveryKeyLen)
		if err != nil {
			t.Error(err)
		}
		if code == nil {
			t.Errorf("Code is nil")
		}

		log.Printf("Code: %+v", code)
	})

	t.Run("Create backup tokens for user", func(t *testing.T) {
		codes, err := bc.CreateCodes(user.GetExtID())
		if err != nil {
			t.Error(err)
		}
		if codes == nil {
			t.Errorf("Code is nil")
		}

		log.Printf("Codes: %+v", codes)
	})

}
