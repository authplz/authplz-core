package main

//import "strings"
import "fmt"
import "errors"
import "net/http"

import "golang.org/x/crypto/bcrypt"

import "github.com/ryankurte/authplz/datastore"

type UserStoreInterface interface {
	AddUser(email string, pass string) (user *datastore.User, err error)
	GetUserByUUID(uuid string) (user *datastore.User, err error)
	GetUserByEmail(email string) (user *datastore.User, err error)
}

type TokenStoreInterface interface {
	AddFidoToken(u *datastore.User, token* datastore.FidoToken) (user *datastore.User, err error)
	AddTotpToken(u *datastore.User, token* datastore.TotpToken) (user *datastore.User, err error)
	GetFidoTokens(u *datastore.User) ([]datastore.FidoToken, error)
	GetTotpTokens(u *datastore.User) ([]datastore.TotpToken, error)
}


type MailInterface interface {
	Send(email string, subject string, body string)
}

// Login status return objects
type LoginStatus struct {
	code    uint64
	message string
}

// User controller status enumerations
const (
    LoginSuccess = iota  // Login complete
    LoginFailure = iota  // Login failed
    LoginPartial = iota  // Further credentials required
)


type UserStatus string
const (
	UserStateDisabled UserStatus = "disabled"
    UserStatePending UserStatus  = "pending"
    UserStateEnabled UserStatus  = "enabled"
    UserStateBlocked UserStatus  = "blocked"
)

func (u *UserStatus) Scan(value interface{}) error { *u = UserStatus(value.([]byte)); return nil }
func (u UserStatus) Value() (driver.Value, error)  { return string(u), nil }


// Login return object instances
var loginSuccess  = LoginStatus{LoginSuccess, "Login successful"}
var loginFailure  = LoginStatus{LoginFailure, "Invalid username or password"}
var loginRequired = LoginStatus{LoginFailure, "Login required"}
var loginPartial  = LoginStatus{LoginFailure, "Second factor required"}
var loginError    = errors.New("internal server error")


type UserController struct {
	userStore UserStoreInterface
	mail      MailInterface
}

func NewUserController(userStore UserStoreInterface, mail MailInterface) UserController {
	return UserController{userStore, mail}
}

func (userController *UserController) CreateUser(email string, pass string) (user *datastore.User, err error) {

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
func (userController *UserController) Login(email string, pass string) (status *LoginStatus, err error) {

	// Fetch user account
	u, err := userController.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		fmt.Println(err)
		return nil, loginError
	}

	// Fake hash if user does not exist, then make login decision after
	// Avoids leaking account info by login timing
	hash := "fake password hash"
	if u != nil {
		hash = u.Password
	}

	// Generate password hash
	hashErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
	if hashErr != nil {
		fmt.Println(hashErr)
		return nil, loginError
	}

	if u.SecondFactors() == true {
		//TODO: prompt for second factor login
		return &loginPartial;
	}

	// Login if user exists and passwords match
	if (u != nil) && (hashErr == nil) {
		//TODO: update login time etc.
		return &loginSuccess, nil
	}

	return &loginFailure, nil
}
