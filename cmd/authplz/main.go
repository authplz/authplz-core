/* AuthPlz Authentication and Authorization Microservice
 * Server entry point
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2018 Ryan Kurte
 */

package main

import (
	"log"

	"github.com/authplz/authplz-core/lib/app"
	"github.com/authplz/authplz-core/lib/config"
)

var version string

func main() {

	log.Printf("AuthPlz (version: %s)", version)

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
