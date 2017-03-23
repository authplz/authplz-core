package oauth

import (
	"github.com/jinzhu/gorm"
)

// User defines the user interface required by the Oauth2 storage module
type User interface {
	GetIntID() uint
	GetExtId() string
}

// BaseStore is the interface required by the oauth module for underlying storage
// This defines required non-oauth methods
type BaseStore interface {
	GetUserByExtID(string) (interface{}, error)
}

// OauthStore is a storage instance for OAuth components
type OauthStore struct {
	db   *gorm.DB
	base BaseStore
}

// NewOauthStore creates an oauthstore from a provided gorm.DB and baseStore instance
func NewOauthStore(db *gorm.DB, baseStore BaseStore) *OauthStore {
	return &OauthStore{db, baseStore}
}

// Sync drops and rebuilds existing OAuth tables
func Sync(dataStore *gorm.DB) *gorm.DB {
	db := dataStore

	db = db.Exec("DROP TABLE IF EXISTS oauth_clients CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS oauth_authorize CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS oauth_session CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS oauth_access CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS oauth_refresh CASCADE;")

	db = db.AutoMigrate(&OauthClient{})
	db = db.AutoMigrate(&OauthSession{})
	db = db.AutoMigrate(&OauthAuthorize{})
	db = db.AutoMigrate(&OauthAccess{})
	db = db.AutoMigrate(&OauthRefresh{})

	return db
}

// Sync Synchronizes the database
// Force causes existing table to be dropped
func (os *OauthStore) Sync(force bool) *gorm.DB {
	return Sync(os.db)
}
