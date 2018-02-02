/*
 * Audit module interfaces
 * This defines the interfaces required by the audit module
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package audit

import (
	"time"
)

// Event Audit event type interface
type Event interface {
	GetUserExtID() string
	GetType() string
	GetTime() time.Time
	GetData() map[string]string
}

// User Audit user type interface
type User interface {
	GetExtID() string
}

// Storer Interface that datastore must implement to provide audit controller
type Storer interface {
	AddAuditEvent(userid, eventType string, eventTime time.Time, data map[string]string) (interface{}, error)
	GetAuditEvents(userid string) ([]interface{}, error)
}
