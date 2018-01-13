package datastore

import (
	"errors"
	"fmt"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"

	"github.com/authplz/authplz-core/lib/controllers/datastore/oauth2"
)

var ErrUserNotFound = errors.New("User account not found")

// DataStore instance storage
type DataStore struct {
	db *gorm.DB
	*oauthstore.OauthStore
}

// QueryFilter filter types
type QueryFilter struct {
	Limit  uint // Number of objects to return
	Offset uint // Offset of objects to return
}

// NewDataStore Create a datastore instance
func NewDataStore(dbString string) (*DataStore, error) {
	// Attempt database connection
	db, err := gorm.Open("postgres", dbString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect database: %s", dbString)
	}

	//db = db.LogMode(true)

	ds := &DataStore{db: db}

	ds.OauthStore = oauthstore.NewOauthStore(db, ds)

	ds.Sync()

	return ds, nil
}

// Close an open datastore instance
func (dataStore *DataStore) Close() {
	dataStore.db.Close()
}

func (dataStore *DataStore) Drop() {
	db := dataStore.db

	db = db.Exec("DROP TABLE IF EXISTS fido_tokens CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS totp_tokens CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS backup_tokens CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS action_tokens CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS audit_events CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS users CASCADE;")

	dataStore.db = db
}

func (dataStore *DataStore) Sync() {
	db := dataStore.db

	db = db.AutoMigrate(&User{})
	db = db.AutoMigrate(&ActionToken{})

	db = db.AutoMigrate(&FidoToken{})
	db = db.AutoMigrate(&TotpToken{})
	db = db.AutoMigrate(&BackupToken{})

	db = db.AutoMigrate(&AuditEvent{})

	db = dataStore.OauthStore.Sync(true)

	dataStore.db = db
}

// ForceSync Drop and create existing tables to match required schema
// WARNING: do not run this on a live database...
func (dataStore *DataStore) ForceSync() {
	dataStore.Drop()
	dataStore.Sync()
}
