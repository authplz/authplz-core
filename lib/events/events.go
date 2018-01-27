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

// Account Events
const (
	AccountCreated      string = "account_created"
	AccountActivated    string = "account_activated"
	AccountNotActivated string = "account_not_activated"
	AccountLocked       string = "account_locked"
	AccountUnlocked     string = "account_unlocked"
	AccountNotUnlocked  string = "account_not_unlocked"
	AccountEnabled      string = "account_enabled"
	AccountDisabled     string = "account_disabled"
	AccountNotEnabled   string = "account_not_enabled"
	AccountDeleted      string = "account_deleted"
	PasswordUpdate      string = "password_update"
	PasswordResetReq    string = "password_reset_request"
)

// 2FA Events
const (
	SecondFactorTotpAdded          string = "totp_added"
	SecondFactorTotpUsed           string = "totp_used"
	SecondFactorTotpRemoved        string = "totp_removed"
	SecondFactorU2FAdded           string = "u2f_added"
	SecondFactorU2FUsed            string = "u2f_used"
	SecondFactorU2FRemoved         string = "u2f_removed"
	SecondFactorBackupCodesAdded   string = "backup_code_added"
	SecondFactorBackupCodesUsed    string = "backup_code_used"
	SecondFactorBackupCodesRemoved string = "backup_code_removed"
)

// Login Events
const (
	LoginSuccess          string = "login_success"
	LoginFailure          string = "login_failure"
	AccountLoginNewDevice string = "login_new_device"
	Logout                string = "logout"
)

// OAuth Events
const (
	OAuthClientCreated      string = "oauth_client_created"
	OAuthClientRemoved      string = "oauth_client_removed"
	OAuthClientAuthorized   string = "oauth_client_authorized"
	OAuthClientDeauthorized string = "oauth_client_deauthorized"
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

// NewData creates a new blank data object
func NewData() map[string]string {
	return make(map[string]string)
}

// Emitter interface for event producers
type Emitter interface {
	SendEvent(interface{})
}
