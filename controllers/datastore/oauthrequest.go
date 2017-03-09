package datastore

import (
	"time"
)

import (
//	"github.com/jinzhu/gorm"
)

// Oauth client application
type OauthRequest struct {
	ID        uint      `gorm:"primary_key" description:"External user ID"`
	CreatedAt time.Time `gorm:"not null"`
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// Getters and Setters
