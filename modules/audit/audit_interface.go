package audit

import (
	"time"
)

// Event Audit event type interface
type Event interface {
	GetUser() interface{}
	GetType() string
	GetTime() time.Time
	GetData() map[string]string
}

// User Audit user type interface
type User interface {
	GetExtId() string
}

// Storer Interface that datastore must implement to provide audit controller
type Storer interface {
	AddAuditEvent(userid, eventType string, eventTime time.Time, data map[string]string) (interface{}, error)
	GetAuditEvents(userid string) ([]interface{}, error)
}
