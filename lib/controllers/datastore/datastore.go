package datastore

import "fmt"

import "github.com/jinzhu/gorm"

import _ "github.com/jinzhu/gorm/dialects/postgres" // Postgres engine required for GORM connection

import (
	"github.com/ryankurte/authplz/lib/controllers/datastore/oauth2"
)

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

	return ds, nil
}

// Close an open datastore instance
func (dataStore *DataStore) Close() {
	dataStore.db.Close()
}

// ForceSync Drop and create existing tables to match required schema
// WARNING: do not run this on a live database...
func (dataStore *DataStore) ForceSync() {
	db := dataStore.db

	db = db.Exec("DROP TABLE IF EXISTS fido_tokens CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS totp_tokens CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS audit_events CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS users CASCADE;")

	db = db.AutoMigrate(&User{})
	db = db.AutoMigrate(&FidoToken{})
	db = db.AutoMigrate(&TotpToken{})
	db = db.AutoMigrate(&AuditEvent{})

	db = dataStore.OauthStore.Sync(true)

	db = db.Model(&User{}).AddUniqueIndex("idx_user_email", "email")
	db = db.Model(&User{}).AddUniqueIndex("idx_user_ext_id", "ext_id")
}