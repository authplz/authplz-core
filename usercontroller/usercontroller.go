package usercontroller

//import "strings"
import "fmt"
import "log"
import "errors"

import "golang.org/x/crypto/bcrypt"

import "github.com/ryankurte/authplz/datastore"

type UserStoreInterface interface {
	AddUser(email string, pass string) (user *datastore.User, err error)
	GetUserByUUID(uuid string) (user *datastore.User, err error)
	GetUserByEmail(email string) (user *datastore.User, err error)
	UpdateUser(user *datastore.User) (*datastore.User, error)
}

type TokenStoreInterface interface {
	AddFidoToken(u *datastore.User, token *datastore.FidoToken) (user *datastore.User, err error)
	AddTotpToken(u *datastore.User, token *datastore.TotpToken) (user *datastore.User, err error)
	GetFidoTokens(u *datastore.User) ([]datastore.FidoToken, error)
	GetTotpTokens(u *datastore.User) ([]datastore.TotpToken, error)
}

type MailInterface interface {
	Send(email string, subject string, body string)
}

// Login status return objects
type LoginStatus struct {
	Code    uint64
	Message string
}

// User controller status enumerations
const (
	LoginCodeSuccess     = iota // Login complete
	LoginCodeFailure     = iota // Login failed
	LoginCodePartial     = iota // Further credentials required
	LoginCodeLocked      = iota // Account locked
	LoginCodeUnactivated = iota // Account not yet activated
	LoginCodeDisabled    = iota // Account disabled
)

// Login return object instances
var LoginSuccess = LoginStatus{LoginCodeSuccess, "Login successful"}
var LoginFailure = LoginStatus{LoginCodeFailure, "Invalid username or password"}
var LoginRequired = LoginStatus{LoginCodeFailure, "Login required"}
var LoginPartial = LoginStatus{LoginCodeFailure, "Second factor required"}
var LoginLocked = LoginStatus{LoginCodeLocked, "User account locked"}
var LoginUnactivated = LoginStatus{LoginCodeUnactivated, "User account not activated"}
var LoginDisabled = LoginStatus{LoginCodeDisabled, "User account disabled"}

var loginError = errors.New("internal server error")

type UserController struct {
	userStore UserStoreInterface
	mail      MailInterface
}

func NewUserController(userStore UserStoreInterface, mail MailInterface) UserController {
	return UserController{userStore, mail}
}

func (userController *UserController) Create(email string, pass string) (user *datastore.User, err error) {

	// Generate password hash
	hash, hashErr := bcrypt.GenerateFromPassword([]byte(pass), 8)
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

	fmt.Printf("User %s created\r\n", email)

	return u, nil
}

func (userController *UserController) Activate(email string) (user *datastore.User, err error) {

	// Fetch user account
	u, err := userController.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		fmt.Println(err)
		return nil, loginError
	}

	u.Activated = true

	u, err = userController.userStore.UpdateUser(u)
	if err != nil {
		// Userstore error, wrap
		fmt.Println(err)
		return nil, loginError
	}

	fmt.Printf("User %s activated\r\n", email)

	return u, nil
}

//TODO: differentiate between login states and internal errors
func (userController *UserController) Login(email string, pass string) (status *LoginStatus, user *datastore.User, err error) {

	// Fetch user account
	u, err := userController.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		fmt.Println(err)
		return nil, nil, loginError
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

		if u != nil {
			u.LoginRetries++

			if u.LoginRetries > 5 {
				fmt.Println("Locking user %s", email)
				u.Locked = true
			}

			u, err = userController.userStore.UpdateUser(u)
			if err != nil {
				// Userstore error, wrap
				fmt.Println(err)
				return nil, nil, loginError
			}
		}

		fmt.Printf("User %s login failed, hash error\r\n", email)

		// Error in case of hash error
		return &LoginFailure, nil, nil
	}

	// Login if user exists and passwords match
	if (u != nil) && (hashErr == nil) {

		if u.Enabled == false {
			//TODO: handle disabled error
			log.Printf("User %s login failed, account disabled\r\n", email)
			return &LoginDisabled, u, nil
		}

		if u.Activated == false {
			//TODO: handle un-activated error
			log.Printf("User %s login failed, account deactivated\r\n", email)
			return &LoginUnactivated, u, nil
		}

		if u.Locked == true {
			//TODO: handle locked error
			log.Printf("User %s login failed, account locked\r\n", email)
			return &LoginLocked, u, nil
		}

		if u.SecondFactors() == true {
			// Prompt for second factor login
			log.Printf("User %s login failed, second factor required\r\n", email)
			return &LoginPartial, u, nil
		}

		log.Printf("User %s login successful\r\n", email)

		//TODO: update login time etc.
		return &LoginSuccess, u, nil
	}

	return &LoginFailure, nil, nil
}
