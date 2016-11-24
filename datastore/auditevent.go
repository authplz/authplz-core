package datastore

import "github.com/jinzhu/gorm"

// Audit events for a login account
type AuditEvent struct {
	gorm.Model
	UserID       uint
	EventType    string
	OriginIP     string
	ForwardedFor string
}

