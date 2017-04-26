package drivers

import (
	"fmt"
	"log"
)

const (
	LoggerDriverID = "logger"
)

// LoggerDriver is a mailer driver that writes mail to logs (for testing use only)
type LoggerDriver struct {
	domain string
	from   string
}

// NewLoggerDriver creates a new mailgun driver instance
func NewLoggerDriver(options map[string]string) (*LoggerDriver, error) {

	domain, ok := options["domain"]
	if !ok || domain == "" {
		return nil, fmt.Errorf("MailgunDriver options requires a 'domain' argument")
	}
	address, ok := options["address"]
	if !ok || address == "" {
		return nil, fmt.Errorf("MailgunDriver options requires a 'address' address argument")
	}

	return &LoggerDriver{
		domain: domain,
		from:   address,
	}, nil
}

// Send writes a message to the console
func (md *LoggerDriver) Send(address, subject, body string) error {

	log.Printf("Mailer.LoggerDriver Send To: %s Subject: %s\n%s", address, subject, body)

	return nil
}
