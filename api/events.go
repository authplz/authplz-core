package api

import (
	"time"
)

type EventType string

const (
	EventAccountCreated      string = "account_created"
	EventAccountActivated    string = "account_activated"
	EventAccountLocked       string = "account_locked"
	EventAccountUnlocked     string = "account_unlocked"
	EventAccountEnabled      string = "account_enabled"
	EventAccountDisabled     string = "account_disabled"
	EventAccountDeleted      string = "account_deleted"
	EventAccountLoginSuccess string = "login_success"
	EventAccountLoginFailure string = "login_failure"
	EventPasswordUpdate      string = "password_update"
)

type AuthPlzEvent struct {
	User interface{}
	Time time.Time
	Type string
	Data map[string]string
}

func (e *AuthPlzEvent) GetType() string            { return e.Type }
func (e *AuthPlzEvent) GetUser() interface{}       { return e.User }
func (e *AuthPlzEvent) GetTime() time.Time         { return e.Time }
func (e *AuthPlzEvent) GetData() map[string]string { return e.Data }

// Create a new AuthPlz event
func NewEvent(u interface{}, eventType string, data map[string]string) *AuthPlzEvent {
	return &AuthPlzEvent{u, time.Now(), eventType, data}
}

// EventEmitter interface for event producers
type EventEmitter interface {
	SendEvent(interface{})
}
