package user

import(
    //"fmt"
    "log"
    "net/http"
    //"encoding/json"
)

import(
    "github.com/ryankurte/authplz/api"
    "github.com/ryankurte/authplz/context"
    "github.com/gocraft/web"
    "github.com/asaskevich/govalidator"
)

// API context instance
type UserApiCtx struct {
    *context.AuthPlzCtx
    um *UserModule
}

func (c *UserApiCtx) Create(rw web.ResponseWriter, req *web.Request) {
    email := req.FormValue("email")
    if !govalidator.IsEmail(email) {
        log.Printf("Create: email parameter required")
        rw.WriteHeader(http.StatusBadRequest)
        return
    }
    password := req.FormValue("password")
    if password == "" {
        log.Printf("Create: password parameter required")
        rw.WriteHeader(http.StatusBadRequest)
        return
    }

    u, e := c.um.Create(email, password)
    if e != nil {
        log.Printf("Create: user creation failed with %s", e)

        if e == ErrorDuplicateAccount {
            c.WriteApiResult(rw, api.ApiResultOk, c.GetApiMessageInst().CreateUserSuccess)
            return
        } else if e == ErrorPasswordTooShort {
            c.WriteApiResult(rw, api.ApiResultError, c.GetApiMessageInst().PasswordComplexityTooLow)
            return
        }

        c.WriteApiResult(rw, api.ApiResultError, c.GetApiMessageInst().InternalError)
        return
    }

    if u == nil {
        log.Printf("Create: user creation failed")
        c.WriteApiResult(rw, api.ApiResultError, c.GetApiMessageInst().InternalError)
        return
    }

    log.Println("Create: Create OK")

    c.WriteApiResult(rw, api.ApiResultOk, c.GetApiMessageInst().CreateUserSuccess)
}
