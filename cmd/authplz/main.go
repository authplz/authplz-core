/* AuthPlz Authentication and Authorization Microservice
 * Server entry point
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2018 Ryan Kurte
 */

package main

import (
	"log"
	"os"

	"github.com/authplz/authplz-core/lib/app"
	"github.com/authplz/authplz-core/lib/config"
)

var version string

func main() {

	log.Printf("AuthPlz (version: %s)", version)

	// Load configuration
	c, err := config.GetConfig()
	if err != nil {
		log.Printf("Error loading config: %s", err)
		os.Exit(-1)
	}

	// Create server instance
	server, err := app.NewServer(*c)
	if err != nil {
		log.Printf("%s", err)
		os.Exit(-2)
	}

	// Launch server
	server.Start()
}
