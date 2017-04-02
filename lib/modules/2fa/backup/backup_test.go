package backup

import (
	"testing"
	//"time"
	"strings"

	"github.com/ryankurte/authplz/lib/controllers/datastore"
	"github.com/ryankurte/authplz/lib/test"
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

	mockEventEmitter := test.MockEventEmitter{}

	// Create backup controller
	bc := NewController("Test Service", dataStore, &mockEventEmitter)

	t.Run("Create backup token", func(t *testing.T) {
		code, err := bc.generateCode(recoveryKeyLen)
		if err != nil {
			t.Error(err)
		}
		if code == nil {
			t.Errorf("Code is nil")
		}

		//log.Printf("Code: %+v", code)
	})

	var tokens *CreateResponse

	t.Run("Create backup tokens for user", func(t *testing.T) {
		codes, err := bc.CreateCodes(user.GetExtID())
		if err != nil {
			t.Error(err)
		}
		if codes == nil {
			t.Errorf("Code is nil")
		}

		tokens = codes
	})

	t.Run("Validate backup tokens for user", func(t *testing.T) {
		code := strings.Join([]string{tokens.Tokens[0].Name, tokens.Tokens[0].Code}, " ")

		ok, err := bc.ValidateCode(user.GetExtID(), code)
		if err != nil {
			t.Error(err)
		}
		if !ok {
			t.Errorf("Backup code validation failed")
		}
	})

	t.Run("Backup codes can only be validated once", func(t *testing.T) {
		code := strings.Join([]string{tokens.Tokens[0].Name, tokens.Tokens[0].Code}, " ")

		ok, err := bc.ValidateCode(user.GetExtID(), code)
		if err != nil {
			t.Error(err)
		}
		if ok {
			t.Errorf("Backup code validation succeeded (expected failure)")
		}
	})

}
