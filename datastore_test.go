
package main

import "fmt"
import "testing"

func TestDatastore(t *testing.T) {
    // Setup user controller for testing
    var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

    // Attempt database connection
    ds := NewDataStore(dbString)
    defer ds.Close()

    ds.db.DropTableIfExists(&User{})
    ds.db.AutoMigrate(&User{})

    var fakeEmail = "test1@abc.com"
    var fakePass = "abcDEF123@"

    // Run tests
    t.Run("Add user", func(t *testing.T) { 
        // Create user
        u, err := ds.AddUser(fakeEmail, fakePass)
        if err != nil {
            t.Error(err)
            return
        }
        if u == nil {
            t.Error("User addition failed")
            return
        }

        fmt.Printf("Created: %+v\n", u)

        u2, err2:= ds.GetUserByEmail(fakeEmail)
        if err2 != nil {
            t.Error(err2)
            return
        }
        if u2 == nil {
            t.Error("User find by email failed")
            return
        }

        if u2.Email != fakeEmail {
            t.Error("Email address mismatch")
            return
        }
        fmt.Printf("Found: %+v\n", u2)

    })

    t.Run("Rejects users with invalid emails", func(t *testing.T) { 
        // Create user
        _, err := ds.AddUser("abcdef", fakePass)
        if err == nil {
            t.Error("Invalid email allowed")
        }
    })

    t.Run("Finds users by email", func(t *testing.T) { 
        // Create user
        u, err:= ds.GetUserByEmail(fakeEmail)
        if err != nil {
            t.Error(err)
            return
        }
        if u == nil {
            t.Error("User find by email failed")
            return
        }

        fmt.Printf("Found: %+v\n", u)

        if u.Email != fakeEmail {
            t.Error("Email address mismatch")
            return
        }
    })

    // Tear down user controller

}



