package authplz

import (
	"github.com/ryankurte/authplz/lib/app"
	"github.com/ryankurte/authplz/lib/config"
)

func main() {

	// Load configuration
	c := config.GetConfig()

	// Create server instance
	server := app.NewServer(*c)

	// Launch server
	server.Start()
}
