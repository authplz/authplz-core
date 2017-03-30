package main

import (
	"github.com/ryankurte/authplz/app"
	"github.com/ryankurte/authplz/config"
)

func main() {

	// Load configuration
	c := config.GetConfig()

	// Create server instance
	server := app.NewServer(*c)

	// Launch server
	server.Start()
}
