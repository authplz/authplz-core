package main

import (
	"log"

	"github.com/ryankurte/authplz/lib/app"
	"github.com/ryankurte/authplz/lib/config"
)

func main() {

	// Load configuration
	c, err := config.GetConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Create server instance
	server := app.NewServer(*c)

	// Launch server
	server.Start()
}
