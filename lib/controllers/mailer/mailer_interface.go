/*
 * Mailer module controller
 * This manages email sending based on system events
 *
 * Copyright 2017 Ryan Kurte
 */

package mailer

import (
	"time"

	"github.com/authplz/authplz-core/lib/api"
)

// MailDriver defines the interface that must be implemented by a concrete mailer driver
type MailDriver interface {
	Send(to, subject, body string) error
}

// Storer required by mailer
type Storer interface {
	GetUserByExtID(extID string) (interface{}, error)
}

// User objects returned by storer
type User interface {
	GetUsername() string
	GetEmail() string
}

// TokenCreator generates action tokens for inclusion in emails
type TokenCreator interface {
	BuildToken(userID string, action api.TokenAction, duration time.Duration) (string, error)
}
