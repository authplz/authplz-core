package drivers

import (
	"log"
)

const (
	LoggerDriverID = "logger"
)

// LoggerDriver is a mailer driver that writes mail to logs (for testing use only)
type LoggerDriver struct {
}

// NewLoggerDriver creates a new mailgun driver instance
func NewLoggerDriver(options map[string]string) (*LoggerDriver, error) {
	return &LoggerDriver{}, nil
}

// Send writes a message to the console
func (md *LoggerDriver) Send(address, subject, body string) error {
	log.Printf("Mailer.LoggerDriver Send To: %s Subject: %s\n%s", address, subject, body)
	return nil
}
