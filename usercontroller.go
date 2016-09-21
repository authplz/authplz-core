
package main

//import "strings"
import "fmt"
import "errors"

import "golang.org/x/crypto/bcrypt"

var ErrLoginFail = errors.New("crypto/bcrypt: hashedSecret too short to be a bcrypted password")

type UserStoreInterface interface {
    AddUser(email string, pass string) (user *User, err error)
    GetUserByUUID(uuid string) (user *User, err error)
    GetUserByEmail(email string) (user *User, err error)
}

type TokenStoreInterface interface {
    AddToken(uuid string)
}

type MailInterface interface {
    Send(email string, subject string, body string)
}

type UserController struct {
    userStore UserStoreInterface
    mail MailInterface
}

func (userController *UserController) CreateUser(email string, pass string) (user *User, err error){

    // Generate password hash
    hash, hashErr := bcrypt.GenerateFromPassword([]byte(pass), 14)
    if hashErr != nil {
        fmt.Println(hashErr)
        return nil, fmt.Errorf("password hash to short")
    }

    // Check if user exists
    u, err := userController.userStore.GetUserByEmail(email)
    if err != nil {
        // Userstore error, wrap
        fmt.Println(err)
        return nil, err
    }

    if u != nil {
        // User exists, fail
        return nil, fmt.Errorf("user account with email %s exists", email)
    }

    // Add user to database (disabled)
    u, err = userController.userStore.AddUser(email, string(hash))
    if err != nil {
        // Userstore error, wrap
        fmt.Println(err)
        return nil, fmt.Errorf("error creating user")
    }

    // Generate user activation token

    // Generate user enrolment email from templates

    // Send account activation token to user email


    return u, nil
}

//TODO: differentiate between login states and internal errors
func (userController *UserController) Login(email string, pass string) (err error) {

    // Fetch user account
    u, err := userController.userStore.GetUserByEmail(email)
    if err != nil {
        // Userstore error, wrap
        fmt.Println(err)
        return fmt.Errorf("internal server error")
    }

    // Fake hash if user does not exist, then make login decision after
    // Avoids leaking account info by login timing
    hash := "fake password hash"
    if(u != nil) {
        hash = u.password
    }

    // Generate password hash
    hashErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
    if hashErr != nil {
        fmt.Println(hashErr)
        return ErrLoginFail
    }

    if u.second_factors == true {
        //TODO: prompt for second factor login
    }

    // Login if user exists and passwords match
    if((u != nil) && (hashErr == nil)) {
        //TODO: update login time etc.
        return nil
    }

    return ErrLoginFail
}







