package main

import (
	"log"

	"github.com/authplz/authplz-core/lib/app"
	"github.com/authplz/authplz-core/lib/config"
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
