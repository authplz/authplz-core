/*
 * Events Module
 * This defines events for asynchronous communication between modules and plugins
 *
 * AuthEngine Project (https://github.com/ryankurte/authengine)
 * Copyright 2017 Ryan Kurte
 */

package events

import (
	"time"
)

// EventType wraps strings for type safety
type EventType string

const (
	// Account Events

	EventAccountCreated   string = "account_created"
	EventAccountActivated string = "account_activated"
	EventAccountLocked    string = "account_locked"
	EventAccountUnlocked  string = "account_unlocked"
	EventAccountEnabled   string = "account_enabled"
	EventAccountDisabled  string = "account_disabled"
	EventAccountDeleted   string = "account_deleted"
	EventPasswordUpdate   string = "password_update"

	// 2FA Events

	Event2faTotpAdded          string = "totp_added"
	Event2faTotpUsed           string = "totp_used"
	Event2faTotpRemoved        string = "totp_removed"
	Event2faU2FAdded           string = "u2f_added"
	Event2faU2FUsed            string = "u2f_used"
	Event2faU2FRemoved         string = "u2f_removed"
	Event2faBackupCodesAdded   string = "backup_code_added"
	Event2faBackupCodesUsed    string = "backup_code_used"
	Event2faBackupCodesRemoved string = "backup_code_removed"

	// Login Events

	EventAccountLoginSuccess   string = "login_success"
	EventAccountLoginFailure   string = "login_failure"
	EventAccountLoginNewDevice string = "login_new_device"

	// OAuth Events

	EventClientCreated      string = "oauth_client_created"
	EventClientRemoved      string = "oauth_client_removed"
	EventClientAuthorized   string = "oauth_client_authorized"
	EventClientDeauthorized string = "oauth_client_deauthorized"
)

// AuthPlzEvent event type for asynchronous communication
type AuthPlzEvent struct {
	UserExtID string
	Time      time.Time
	Type      string
	Data      map[string]string
}

// GetType fetches the event type
func (e *AuthPlzEvent) GetType() string { return e.Type }

// GetUserExtID fetches the associated external user id
func (e *AuthPlzEvent) GetUserExtID() string { return e.UserExtID }

// GetTime fetches the event originator time
func (e *AuthPlzEvent) GetTime() time.Time { return e.Time }

// GetData fetches data associated with the event
func (e *AuthPlzEvent) GetData() map[string]string { return e.Data }

// NewEvent Create a new AuthPlz event
func NewEvent(userExtID, eventType string, data map[string]string) *AuthPlzEvent {
	return &AuthPlzEvent{userExtID, time.Now(), eventType, data}
}

// EventEmitter interface for event producers
type EventEmitter interface {
	SendEvent(interface{})
}
