/* AuthPlz Authentication and Authorization Microservice
 * Mailgun mailer driver
 *
 * Copyright 2018 Ryan Kurte
 */

package drivers

import (
	"log"

	"fmt"
	"gopkg.in/mailgun/mailgun-go.v1"
)

const (
	MailgunDriverID = "mailgun"
)

// MailgunDriver is a mailer driver using the mailgun API
type MailgunDriver struct {
	domain   string
	from     string
	key      string
	secret   string
	mg       mailgun.Mailgun
	testMode bool
}

// NewMailgunDriver creates a new mailgun driver instance
func NewMailgunDriver(options map[string]string) (*MailgunDriver, error) {

	domain, ok := options["domain"]
	if !ok || domain == "" {
		return nil, fmt.Errorf("MailgunDriver options requires a 'domain' argument")
	}
	address, ok := options["address"]
	if !ok || address == "" {
		return nil, fmt.Errorf("MailgunDriver options requires a 'address' address argument")
	}
	APIKey, ok := options["key"]
	if !ok || APIKey == "" {
		return nil, fmt.Errorf("MailgunDriver options requires a 'key' argument")
	}
	APISecret, ok := options["secret"]
	if !ok || APISecret == "" {
		return nil, fmt.Errorf("MailgunDriver options requires a 'secret' address argument")
	}

	// Attempt connection to mailgun
	mg := mailgun.NewMailgun(domain, APISecret, APIKey)

	return &MailgunDriver{
		domain:   domain,
		from:     address,
		key:      APIKey,
		secret:   APISecret,
		mg:       mg,
		testMode: false,
	}, nil
}

func (md *MailgunDriver) Send(address, subject, body string) error {
	// Build mailgun message
	message := md.mg.NewMessage(md.from, subject, "", address)
	message.SetTracking(true)
	message.SetHtml(body)

	// Enable test mode if set
	if md.testMode == true {
		message.EnableTestMode()
	}

	// Attempt to send message
	_, _, err := md.mg.Send(message)
	if err != nil {
		log.Printf("MailgunDriver.Send error: %s", err)
		return err
	}

	return nil
}

func (md *MailgunDriver) SetTestMode(m bool) {
	md.testMode = m
}
