/*
 * Mailer module controller
 * This defines the API methods bound to the TOTP module
 *
 * AuthPlz Project (https://github.com/ryankurte/AuthPlz)
 * Copyright 2017 Ryan Kurte
 */

package mailer

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/ryankurte/authplz/lib/controllers/mailer/drivers"
)

// MailDriver defines the interface that must be implemented by a mailer driver
type MailDriver interface {
	Send(to, subject, body string) error
	SetTestMode(m bool)
}

// Mail controller object
type MailController struct {
	domain      string
	templateDir string
	templates   map[string]template.Template
	driver      MailDriver
}

// Fields required for a signup email
type MailFields struct {
	Domain      string
	UserName    string
	ServiceName string
	ActionUrl   string
}

// Standard mailing templates (required for MailController creation)
var templateNames = [...]string{"signup", "passwordreset", "loginnotice"}

// Instantiate a mail controller
func NewMailController(driver, domain, key, secret, templateDir string) (*MailController, error) {
	var templates map[string]template.Template = make(map[string]template.Template)

	var d MailDriver
	// Load driver
	switch driver {
	case drivers.MailgunDriverID:
		d = drivers.NewMailgunDriver(domain, key, secret)
	default:
		return nil, fmt.Errorf("NewMailController error: unrecognised driver %s", driver)
	}

	// Load templates from specified directory
	for _, name := range templateNames {
		tpl, err := template.ParseFiles(templateDir + "/" + name + ".tmpl")
		if err != nil {
			return nil, err
		}
		templates[name] = *tpl
	}

	return &MailController{domain: domain, templateDir: templateDir, templates: templates, driver: d}, nil
}

// Enable test mode (blocks mail sending)
func (mc *MailController) SetTestMode() {
	mc.driver.SetTestMode(true)
}

// Send an item of mail
func (mc *MailController) SendMail(email string, subject string, body string) error {
	return mc.driver.Send(email, subject, body)
}

// Send a signup (activation) email to the provided address
func (mc *MailController) SendSignup(email string, data MailFields) error {
	buf := new(bytes.Buffer)
	tmpl, ok := mc.templates["signup"]
	if !ok {
		return fmt.Errorf("template %s not found", "signup")
	}
	err := tmpl.Execute(buf, data)
	if err != nil {
		return err
	}

	return mc.SendMail(email, data.ServiceName+" account activation", buf.String())
}

// Send a password reset email to the provided address
func (mc *MailController) SendPasswordReset(email string, data MailFields) error {
	buf := new(bytes.Buffer)
	tmpl, ok := mc.templates["passwordreset"]
	if !ok {
		return fmt.Errorf("template %s not found", "signup")
	}
	err := tmpl.Execute(buf, data)
	if err != nil {
		return err
	}

	return mc.SendMail(email, data.ServiceName+" password reset", buf.String())
}
