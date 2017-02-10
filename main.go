package main

import "github.com/ryankurte/authplz/app"

func main() {

	// Load configuration
	c := app.GetConfig()

	// Create server instance
	server := app.NewServer(*c)

	// Launch server
	server.Start()
}
