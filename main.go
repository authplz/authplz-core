package main

import "log"

import "github.com/kelseyhightower/envconfig"
import "github.com/ryankurte/authplz/app"

func main() {

	// Fetch default configuration
	c, err := app.DefaultConfig()
	if err != nil {
        log.Fatal(err.Error())
    }

	// Parse config structure
    err = envconfig.Process("authplz", c)
    if err != nil {
        log.Fatal(err.Error())
    }

    // Create server instance
	server := app.NewServer(*c)

	// Launch server
	server.Start()
}
