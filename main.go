package main

import "os"

//import "strings"
import "fmt"
import "net/http"

//import "encoding/json"

import "github.com/gocraft/web"

import "github.com/asaskevich/govalidator"

import "github.com/ryankurte/authplz/usercontroller"
import "github.com/ryankurte/authplz/datastore"

type AuthPlzCtx struct {
	port           string
	address        string
	userController *usercontroller.UserController
}

func (c *AuthPlzCtx) Create(rw web.ResponseWriter, req *web.Request) {
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		fmt.Fprint(rw, "email parameter required")
		return
	}
	password := req.FormValue("password")
	if password == "" {
		fmt.Fprint(rw, "password parameter required")
		return
	}

	rw.WriteHeader(501)
}

func (c *AuthPlzCtx) Login(rw web.ResponseWriter, req *web.Request) {
	email := req.FormValue("email")
	if !govalidator.IsEmail(email) {
		fmt.Fprint(rw, "email parameter required")
		return
	}
	password := req.FormValue("password")
	if password == "" {
		fmt.Fprint(rw, "password parameter required")
		return
	}

	rw.WriteHeader(501)
}

func (c *AuthPlzCtx) Logout(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(501)
}

func (c *AuthPlzCtx) Status(rw web.ResponseWriter, req *web.Request) {
	rw.WriteHeader(501)
}

func main() {
	var port string = "9000"
	var address string = "loalhost"
	var dbString string = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

	// Parse environmental variables
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}

	// Attempt database connection
	ds := datastore.NewDataStore(dbString)
	defer ds.Close()

	// Create controllers
	uc := usercontroller.NewUserController(&ds, nil)

	// Create router
	router := web.New(AuthPlzCtx{port, address, &uc}).
		Middleware(web.LoggerMiddleware).
		Middleware(web.ShowErrorsMiddleware).
		Post("/login", (*AuthPlzCtx).Login).
		Post("/create", (*AuthPlzCtx).Create).
		Get("/logout", (*AuthPlzCtx).Logout).
		Get("/status", (*AuthPlzCtx).Status)

	// Start listening
	fmt.Println("Listening at: " + port)
	http.ListenAndServe("localhost:"+port, router)
}
