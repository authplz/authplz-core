/* AuthPlz Authentication and Authorization Microservice
 * Mailgun mailer tests
 *
 * Copyright 2018 Ryan Kurte
 */
package drivers

import (
	"fmt"
	"os"
	"testing"
)

func TestMailController(t *testing.T) {

	options := make(map[string]string)

	// Fetch options from environment
	options["domain"] = os.Getenv("AUTHPLZ_MG_DOMAIN")
	options["address"] = os.Getenv("AUTHPLZ_MG_ADDRESS")
	options["key"] = os.Getenv("AUTHPLZ_MG_APIKEY")
	options["secret"] = os.Getenv("AUTHPLZ_MG_PRIKEY")

	// Skip tests if domain is not valid
	if v, ok := options["domain"]; !ok || v == "" {
		t.SkipNow()
		return
	}

	testAddress := "test@kurte.nz"

	// Create driver for test use
	d, err := NewMailgunDriver(options)
	if err != nil {
		t.Error(err)
		return
	}

	d.SetTestMode(true)

	// Run tests
	t.Run("Can send emails", func(t *testing.T) {
		err := d.Send(testAddress, "test subject", "test body")
		if err != nil {
			fmt.Println(err)
			t.Error(err)
		}
	})

}
