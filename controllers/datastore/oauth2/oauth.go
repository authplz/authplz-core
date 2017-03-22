package oauth2

import (
	"github.com/jinzhu/gorm"
)

type User interface {
	GetIntID() uint
	GetExtId() string
}

type BaseStore interface {
	GetUserByExtID(string) (interface{}, error)
}

type OauthStore struct {
	db   *gorm.DB
	base BaseStore
}

func NewOauthStore(db *gorm.DB, baseStore BaseStore) *OauthStore {
	return &OauthStore{db, baseStore}
}

func Sync(dataStore *gorm.DB) *gorm.DB {
	db := dataStore

	db = db.Exec("DROP TABLE IF EXISTS oauth_clients CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS oauth_authorizes CASCADE;")

	db = db.AutoMigrate(&OauthClient{})
	db = db.AutoMigrate(&OauthAuthorize{})

	return db
}
