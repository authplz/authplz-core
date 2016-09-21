package main

import "os"
//import "strings"
import "fmt"
import "net/http"
//import "encoding/json"

import "github.com/gocraft/web"

import "github.com/jinzhu/gorm"
import _ "github.com/jinzhu/gorm/dialects/postgres"

import "github.com/asaskevich/govalidator"

type AuthPlzCtx struct {
    port int
    address string
    userController UserController
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

func main() {
    var port string = "9000"
    var dbString string = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

    // Create router
    router := web.New(AuthPlzCtx{}).
        Middleware(web.LoggerMiddleware).
        Middleware(web.ShowErrorsMiddleware).
        Post("/login", (*AuthPlzCtx).Login).
        Post("/create", (*AuthPlzCtx).Create)

    if os.Getenv("PORT") != "" {
        port = os.Getenv("PORT")
    }

    db, err := gorm.Open("postgres", dbString)
    if err != nil {
        fmt.Println("failed to connect database: " + dbString)
        panic(err)
    }
    defer db.Close()

    db.AutoMigrate(&User{})

    // Start listening
    fmt.Println("Listening at: " + port)
    http.ListenAndServe("localhost:" + port, router)
}
