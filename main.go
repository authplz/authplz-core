package main

import "os"

import "github.com/ryankurte/authplz/app"


func main() {
	var port string = "9000"
	var address string = "localhost"
	var dbString string = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Parse environmental variables
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}

	server := app.NewServer(address, port, dbString)

	server.Start()
}
