/*
 * Mailer module controller
 * This manages email sending based on system events
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package mailer

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/authplz/authplz-core/lib/api"
	"github.com/authplz/authplz-core/lib/controllers/datastore"
	"github.com/authplz/authplz-core/lib/events"
)

type FakeTokenGenerator struct {
}

func (ftg *FakeTokenGenerator) BuildToken(userID string, action api.TokenAction, duration time.Duration) (string, error) {
	return fmt.Sprintf("%s:%s:%s", userID, action, duration), nil
}

type FakeStorer struct {
	Users map[string]datastore.User
}

func (fs *FakeStorer) GetUserByExtID(extID string) (interface{}, error) {
	u, ok := fs.Users[extID]
	if !ok {
		return nil, fmt.Errorf("User %s not found", extID)
	}
	return &u, nil
}

type FakeDriver struct {
	To      string
	Subject string
	Body    string
}

func (fd *FakeDriver) Send(to, subject, body string) error {
	fd.To = to
	fd.Subject = subject
	fd.Body = body
	return nil
}

func TestMailController(t *testing.T) {

	var mc *MailController

	options := make(map[string]string)
	options["domain"] = "kurte.nz"
	options["address"] = "admin@kurte.nz"

	testAddress := "test@kurte.nz"

	storer := FakeStorer{make(map[string]datastore.User)}
	storer.Users["test-id"] = datastore.User{
		ExtID:    "test-id",
		Username: "test-username",
		Email:    "test-email",
	}

	driver := FakeDriver{}

	// Run tests
	t.Run("Create mail controller", func(t *testing.T) {
		lmc, err := NewMailController("AuthPlz Test", "test.kurte.nz", "logger", options, &storer, &FakeTokenGenerator{}, "../../../templates")
		assert.Nil(t, err)

		lmc.driver = &driver
		mc = lmc
	})

	t.Run("Can send emails", func(t *testing.T) {
		err := mc.SendMail(testAddress, "test subject", "test body")
		assert.Nil(t, err)
	})

	t.Run("Can send activation emails", func(t *testing.T) {
		data := make(map[string]string)
		data["ServiceName"] = mc.appName
		data["ActionURL"] = "https://not.a.url/action?token=reset"
		data["UserName"] = "TestUser"

		err := mc.SendActivation(testAddress, data)
		assert.Nil(t, err)
		assert.EqualValues(t, driver.Subject, fmt.Sprintf("%s Account Activation", mc.appName))
	})

	t.Run("Can send password reset emails", func(t *testing.T) {
		data := make(map[string]string)
		data["ServiceName"] = mc.appName
		data["ActionURL"] = "https://not.a.url/recovery?token=reset"
		data["UserName"] = "TestUser"

		err := mc.SendPasswordReset(testAddress, data)
		assert.Nil(t, err)
		assert.EqualValues(t, driver.Subject, fmt.Sprintf("%s Password Reset", mc.appName))
	})

	t.Run("Handles AccountCreated event", func(t *testing.T) {
		e := events.AuthPlzEvent{
			UserExtID: "test-id",
			Time:      time.Now(),
			Type:      events.AccountCreated,
			Data:      make(map[string]string),
		}

		err := mc.HandleEvent(&e)
		assert.Nil(t, err)

		assert.EqualValues(t, driver.Subject, fmt.Sprintf("%s Account Activation", mc.appName))
	})

	t.Run("Handles StartRecovery event", func(t *testing.T) {
		e := events.AuthPlzEvent{
			UserExtID: "test-id",
			Time:      time.Now(),
			Type:      events.PasswordResetReq,
			Data:      make(map[string]string),
		}

		err := mc.HandleEvent(&e)
		assert.Nil(t, err)

		assert.EqualValues(t, driver.Subject, fmt.Sprintf("%s Password Reset", mc.appName))
	})

}
