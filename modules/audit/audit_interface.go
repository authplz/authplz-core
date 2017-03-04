package audit

import (
	"time"
)

// Audit event type interface
type AuditEventI interface {
	GetUser() interface{}
	GetType() string
	GetTime() time.Time
	GetData() map[string]string
}

// Audit user type interface
type AuditUserI interface {
	GetExtId() string
}

// Interface that datastore must implement to provide audit controller
type AuditStoreInterface interface {
	AddAuditEvent(userid, eventType string, eventTime time.Time, data map[string]string) (interface{}, error)
	GetAuditEvents(userid string) ([]interface{}, error)
}
