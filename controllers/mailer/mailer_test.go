package mailer

import "testing"
import "fmt"
import "os"

func TestMailController(t *testing.T) {

	var mc *MailController

	mgDomain := os.Getenv("MG_DOMAIN")
	mgApiKey := os.Getenv("MG_APIKEY")
	mgPriKey := os.Getenv("MG_PRIKEY")

	// Run tests
	t.Run("Create mail controller", func(t *testing.T) {
		lmc, err := NewMailController(mgDomain, mgPriKey, mgApiKey, "../../templates")
		if err != nil {
			fmt.Println(err)
			t.Error(err)
		}
		lmc.SetTestMode()
		mc = lmc
	})

	t.Run("Can send emails", func(t *testing.T) {
		if mgDomain == "" {
			t.Skip("skipping mailgun tests (no API config)")
		}
		err := mc.SendMail("test@"+mgDomain, "test subject", "test body")
		if err != nil {
			fmt.Println(err)
			t.Error(err)
		}
	})

	t.Run("Can send signup emails", func(t *testing.T) {
		if mgDomain == "" {
			t.Skip("skipping mailgun tests (no API config)")
		}

		sf := MailFields{
			UserName:    "TestUser",
			ServiceName: "AuthPlzTest",
			ActionUrl:   "https://not.a.url/action?token=activate",
		}

		err := mc.SendSignup("test@"+mgDomain, sf)
		if err != nil {
			fmt.Println(err)
			t.Error(err)
		}
	})

	t.Run("Can send password reset emails", func(t *testing.T) {
		if mgDomain == "" {
			t.Skip("skipping mailgun tests (no API config)")
		}

		sf := MailFields{
			UserName:    "TestUser",
			ServiceName: "AuthPlzTest",
			ActionUrl:   "https://not.a.url/action?token=reset",
		}

		err := mc.SendPasswordReset("test@"+mgDomain, sf)
		if err != nil {
			fmt.Println(err)
			t.Error(err)
		}
	})

}
