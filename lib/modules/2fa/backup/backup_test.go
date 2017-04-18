package backup

import (
	"testing"
	//"time"
	"log"
	"strings"

	"github.com/stretchr/testify/assert"

	"github.com/ryankurte/authplz/lib/config"
	"github.com/ryankurte/authplz/lib/controllers/datastore"
	"github.com/ryankurte/authplz/lib/test"
	"time"
)

func TestBackupModule(t *testing.T) {
	var fakeEmail = "test@abc.com"
	var fakePass = "abcDEF123@abcDEF123@"
	var fakeName = "user.sdfsfdF"

	c, _ := config.DefaultConfig()

	// Attempt database connection
	dataStore, err := datastore.NewDataStore(c.Database)
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
		assert.Nil(t, err)
		assert.NotNil(t, code)
	})

	var tokens *CreateResponse

	t.Run("Create backup tokens for user", func(t *testing.T) {
		codes, err := bc.CreateCodes(user.GetExtID())
		assert.Nil(t, err)
		assert.NotNil(t, codes)

		tokens = codes
	})

	t.Run("Validate backup tokens for user", func(t *testing.T) {
		code := strings.Join([]string{tokens.Tokens[0].Name, tokens.Tokens[0].Code}, " ")

		// TODO: resolve intermittent failure (I think due to database sync time)

		ok, err := bc.ValidateCode(user.GetExtID(), code)
		assert.Nil(t, err)

		if !ok {
			t.Errorf("Backup code validation failed (expected success)")
		}
	})

	t.Run("Backup codes can only be validated once", func(t *testing.T) {
		code := strings.Join([]string{tokens.Tokens[0].Name, tokens.Tokens[0].Code}, " ")

		ok, err := bc.ValidateCode(user.GetExtID(), code)
		assert.Nil(t, err)
		if ok {
			t.Errorf("Backup code validation succeeded (expected failure)")
		}
	})

}
