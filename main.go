package main

import "os"
//import "strings"
import "fmt"
import "net/http"
import "github.com/gocraft/web"

import "github.com/jinzhu/gorm"
import _ "github.com/jinzhu/gorm/dialects/postgres"

type Context struct {
    HelloCount int
}

func main() {
    var port string = "9000"
    var dbString string = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

    // Create router
    router := web.New(Context{}).
        Middleware(web.LoggerMiddleware).
        Middleware(web.ShowErrorsMiddleware)

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
