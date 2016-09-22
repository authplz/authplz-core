
package main

import "testing"

func TestUserController(t *testing.T) {
    // Setup user controller for testing
    var fakeEmail = "test@abc.com"
    var fakePass = "abcDEF123@"
    var dbString = "host=localhost user=postgres dbname=postgres sslmode=disable password=postgres"

    // Attempt database connection
    ds := NewDataStore(dbString)

    // Create controllers
    uc := NewUserController(&ds, nil)

    // Run tests
    t.Skip("Create user", func(t *testing.T) { 
        u, err := uc.CreateUser(fakeEmail, fakePass)
        if err != nil {
            t.Error(err)
        }
        if u == nil {
            t.Error("User creation failed")
        }
    })

    // Tear down user controller

}