package mailer

import (
	"fmt"
	"testing"

	"github.com/ryankurte/authplz/lib/controllers/datastore"
)

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
		Username: "test-username",
		Email:    "test-email",
	}

	// Run tests
	t.Run("Create mail controller", func(t *testing.T) {
		lmc, err := NewMailController("AuthPlz Test", "logger", options, &storer, "../../../templates")
		if err != nil {
			fmt.Println(err)
			t.Error(err)
		}

		//lmc.driver = &FakeDriver{}
		mc = lmc
	})

	t.Run("Can send emails", func(t *testing.T) {
		err := mc.SendMail(testAddress, "test subject", "test body")
		if err != nil {
			fmt.Println(err)
			t.Error(err)
		}
	})

	t.Run("Can send activation emails", func(t *testing.T) {
		data := make(map[string]string)
		data["ServiceName"] = mc.appName
		data["ActionURL"] = "https://not.a.url/action?token=reset"
		data["UserName"] = "TestUser"

		err := mc.SendActivation(testAddress, data)
		if err != nil {
			fmt.Println(err)
			t.Error(err)
		}
	})

	t.Run("Can send password reset emails", func(t *testing.T) {
		data := make(map[string]string)
		data["ServiceName"] = mc.appName
		data["ActionURL"] = "https://not.a.url/recovery?token=reset"
		data["UserName"] = "TestUser"

		err := mc.SendPasswordReset(testAddress, data)
		if err != nil {
			fmt.Println(err)
			t.Error(err)
		}
	})

}
