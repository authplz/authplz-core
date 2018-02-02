/* AuthPlz Authentication and Authorization Microservice
 * Logging mailer driver
 *
 * Copyright 2018 Ryan Kurte
 */

package drivers

import (
	"log"
)

const (
	LoggerDriverID = "logger"
)

// LoggerDriver is a mailer driver that writes mail to logs (for testing use only)
type LoggerDriver struct {
	options map[string]string
}

// NewLoggerDriver creates a new mailgun driver instance
func NewLoggerDriver(options map[string]string) (*LoggerDriver, error) {
	return &LoggerDriver{options}, nil
}

// Send writes a message to the console
func (md *LoggerDriver) Send(address, subject, body string) error {
	if m, ok := md.options["mode"]; ok && m == "silent" {
		return nil
	}
	log.Printf("Mailer.LoggerDriver Send To: %s Subject: %s\n%s", address, subject, body)
	return nil
}
