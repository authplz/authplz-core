package main

import "fmt"
import "log"
import "net/http"
import "encoding/json"

import "github.com/gocraft/web"
import "github.com/asaskevich/govalidator"

import "github.com/ryankurte/authplz/usercontroller"
import "github.com/ryankurte/authplz/token"

// Common API response object
type ApiResponse struct {
    Result  string
    Message string
}

// Helper to write API results out
func (ctx *AuthPlzCtx) WriteApiResult(w http.ResponseWriter, result string, message string) {
    apiResp := ApiResponse{Result: result, Message: message}

    js, err := json.Marshal(apiResp)
    if err != nil {
        log.Print(err)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.Write(js)
}

// Create a user
func (c *AuthPlzCtx) Create(rw web.ResponseWriter, req *web.Request) {
    email := req.FormValue("email")
    if !govalidator.IsEmail(email) {
        fmt.Printf("email parameter required")
        rw.WriteHeader(http.StatusBadRequest)
        return
    }
    password := req.FormValue("password")
    if password == "" {
        fmt.Printf("password parameter required")
        rw.WriteHeader(http.StatusBadRequest)
        return
    }

    u, e := c.global.userController.Create(email, password)
    if e != nil {
        fmt.Fprint(rw, "Error: %s", e)
        rw.WriteHeader(500)
        return
    }

    if u == nil {
        rw.WriteHeader(http.StatusInternalServerError)
        return
    }

    log.Println("Login OK")

    rw.WriteHeader(http.StatusOK)
}

// Login to a user account
func (c *AuthPlzCtx) Login(rw web.ResponseWriter, req *web.Request) {
    // Fetch parameters
    email := req.FormValue("email")
    if !govalidator.IsEmail(email) {
        rw.WriteHeader(http.StatusBadRequest)
        fmt.Println("email parameter required")
        return
    }
    password := req.FormValue("password")
    if password == "" {
        rw.WriteHeader(http.StatusBadRequest)
        fmt.Println("password parameter required")
        return
    }

    // Attempt login
    l, u, e := c.global.userController.Login(email, password)
    if e != nil {
        rw.WriteHeader(http.StatusUnauthorized)
        fmt.Printf("Error: %s", e)
        return
    }

    // Handle simple logins
    if l == &usercontroller.LoginSuccess {
        log.Println("Login OK")

        // Create session
        c.LoginUser(u, rw, req)
        c.WriteApiResult(rw, ApiResultOk, ApiMessageLoginSuccess)
        return
    }

    // Load flashes if they exist
    flashes := c.session.Flashes()

    // Handle not yet activated accounts
    if l == &usercontroller.LoginUnactivated {
        if len(flashes) > 0 {
            activateToken := flashes[0]

            claims, err := c.global.tokenController.ParseToken(activateToken.(string))
            if err != nil {
                fmt.Printf("Invalid token\n")
                c.WriteApiResult(rw, ApiResultError, ApiMessageInvalidToken)
                return
            }

            fmt.Printf("Valid token found\n")
            if claims.Action == token.TokenActionActivate {
                fmt.Printf("Activation token\n")

                if u.UUID == claims.Subject {
                    fmt.Printf("Activating user\n")

                    c.global.userController.Activate(u.Email)

                    // Create session
                    c.LoginUser(u, rw, req)
                    c.WriteApiResult(rw, ApiResultOk, ApiMessageActivationSuccessful)

                } else {
                    fmt.Printf("Subject mismatch user\n")
                }

            } else {
                fmt.Printf("Invalid token\n")
                rw.WriteHeader(http.StatusBadRequest)
                return
            }

            rw.WriteHeader(http.StatusOK)

        } else {
            log.Println("Account not activated")
            //TODO: prompt for activation (resend email?)
            rw.WriteHeader(http.StatusUnauthorized)
            //c.WriteApiResult(rw, ApiResultError, usercontroller.LoginUnactivated.Message);
        }

        return
    }

    // TODO: handle disabled accounts
    if l == &usercontroller.LoginDisabled {

    }

    // Handle partial logins (2FA)
    if l == &usercontroller.LoginPartial {
        log.Println("Partial login")
        //TODO: fetch tokens and set flash
        rw.WriteHeader(http.StatusNotImplemented)
        return
    }

    fmt.Printf("login endpoint: login failed %s", e)
    rw.WriteHeader(http.StatusUnauthorized)
}

func (c *AuthPlzCtx) Action(rw web.ResponseWriter, req *web.Request) {

    // Grab token string from get or post request
    var tokenString string
    tokenString = req.FormValue("token")
    if tokenString == "" {
        req.URL.Query().Get("token")
    }
    if tokenString == "" {
        rw.WriteHeader(http.StatusBadRequest)
        fmt.Println("token parameter required")
        return
    }

    // If the user isn't logged in
    if c.userid == "" {
        fmt.Printf("Received token, login required (saving to flash)\n")

        // Clear existing flashes (by reading)
        _ = c.session.Flashes()

        // Add token to flash and redirect
        c.session.AddFlash(tokenString)
        c.session.Save(req.Request, rw)

        c.WriteApiResult(rw, ApiResultOk, "Saved token")
        //TODO: redirect to login

    } else {
        // Check token validity
        claims, err := c.global.tokenController.ParseToken(tokenString)
        if err != nil {
            fmt.Printf("Invalid token\n")
            c.WriteApiResult(rw, ApiResultError, "Invalid token")
            return
        }

        fmt.Printf("Valid token found (claims: %+v)\n", claims)
        //TODO: execute action token on signed in user
        rw.WriteHeader(http.StatusOK)
    }
}

// Logout of a user account
func (c *AuthPlzCtx) Test(rw web.ResponseWriter, req *web.Request) {
    // Get the previously flashes, if any.
    if flashes := c.session.Flashes(); len(flashes) > 0 {
        fmt.Printf("Flashes: %+v\n", flashes)
    } else {
        // Set a new flash.
        c.session.AddFlash("Hello, flash messages world!")
    }
    c.session.Save(req.Request, rw)
    c.WriteApiResult(rw, ApiResultOk, "Test Response")
}

// Get user login status
func (c *AuthPlzCtx) Status(rw web.ResponseWriter, req *web.Request) {
    if c.userid == "" {
        c.WriteApiResult(rw, ApiResultError, "You must be signed in to view this page")
    } else {
        c.WriteApiResult(rw, ApiResultOk, "Signed in")
    }
}

// Get user login status
func (c *AuthPlzCtx) Logout(rw web.ResponseWriter, req *web.Request) {
    if c.userid == "" {
        c.WriteApiResult(rw, ApiResultError, "You must be signed sign out")
    } else {
        c.LogoutUser(rw, req)
        c.WriteApiResult(rw, ApiResultOk, ApiMessageLogoutSuccess)
    }
}

