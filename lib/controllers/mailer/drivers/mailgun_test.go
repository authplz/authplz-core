package drivers

import (
	"fmt"
	"os"
	"testing"
)

func TestMailController(t *testing.T) {

	var driver *MailgunDriver

	options := make(map[string]string)

	options["domain"] = os.Getenv("MG_DOMAIN")
	options["address"] = os.Getenv("MG_ADDRESS")
	options["key"] = os.Getenv("MG_APIKEY")
	options["secret"] = os.Getenv("MG_PRIKEY")

	testAddress := "test@kurte.nz"

	// Run tests
	t.Run("Create mail controller", func(t *testing.T) {
		d, err := NewMailgunDriver(options)
		if err != nil {
			fmt.Println(err)
			t.Error(err)
		}
		d.SetTestMode(true)
		driver = d
	})

	t.Run("Can send emails", func(t *testing.T) {
		err := driver.Send(testAddress, "test subject", "test body")
		if err != nil {
			fmt.Println(err)
			t.Error(err)
		}
	})

}
