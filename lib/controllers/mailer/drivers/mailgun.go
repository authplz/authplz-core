package drivers

import (
	"fmt"
	"log"

	"gopkg.in/mailgun/mailgun-go.v1"
)

const (
	MailgunDriverID = "mailgun"
)

type MailgunDriver struct {
	domain   string
	key      string
	secret   string
	mg       mailgun.Mailgun
	testMode bool
}

func NewMailgunDriver(domain, key, secret string) *MailgunDriver {

	// Attempt connection to mailgun
	mg := mailgun.NewMailgun(domain, key, secret)

	return &MailgunDriver{
		domain:   domain,
		key:      key,
		secret:   secret,
		mg:       mg,
		testMode: false,
	}
}

func (md *MailgunDriver) Send(address, subject, body string) error {
	from := fmt.Sprintf("noreply@%s", md.domain)

	// Build mailgun message
	message := md.mg.NewMessage(from, subject, "", address)
	message.SetTracking(true)
	message.SetHtml(body)

	// Enable test mode if set
	if md.testMode == true {
		message.EnableTestMode()
	}

	// Attempt to send message
	_, id, err := md.mg.Send(message)
	if err != nil {
		log.Fatal(err)
		return err
	}

	log.Printf("MailgunDriver.Send: Sent message id: %s", id)

	return nil
}

func (md *MailgunDriver) SetTestMode(m bool) {
	md.testMode = m
}
