package usercontroller

//import "strings"
import "fmt"
import "errors"

import "golang.org/x/crypto/bcrypt"

import "github.com/ryankurte/authplz/datastore"

type UserInterface interface {
	UUID() string
	Email() string
	Password() string
	SetPassword(pass string)
	Activated() bool
	SetActivated(activated bool)
	Enabled() bool
	SetEnabled(enabled bool)
	Locked() bool
	SetLocked(locked bool)
	Admin() bool
	SetAdmin(admin bool)
	LoginRetries() uint
	ClearLoginRetries()
}

type User struct {
    UUID         string `sql:"not null;unique"`
    Email        string `sql:"not null;unique"`
    Password     string `sql:"not null"`
    Activated    bool   `sql:"not null; default:false"`
    Enabled      bool   `sql:"not null; default:false"`
    Locked       bool   `sql:"not null; default:false"`
    Admin        bool   `sql:"not null; default:false"`
    LoginRetries uint   `sql:"not null; default:0"`
}

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
	code    uint64
	message string
}

// User controller status enumerations
const (
	LoginSuccess     = iota // Login complete
	LoginFailure     = iota // Login failed
	LoginPartial     = iota // Further credentials required
	LoginLocked      = iota // Account locked
	LoginUnactivated = iota // Account not yet activated
	LoginDisabled    = iota // Account disabled
)

// Login return object instances
var loginSuccess = LoginStatus{LoginSuccess, "Login successful"}
var loginFailure = LoginStatus{LoginFailure, "Invalid username or password"}
var loginRequired = LoginStatus{LoginFailure, "Login required"}
var loginPartial = LoginStatus{LoginFailure, "Second factor required"}
var loginLocked = LoginStatus{LoginLocked, "User account locked"}
var loginUnactivated = LoginStatus{LoginUnactivated, "User account not activated"}
var loginDisabled = LoginStatus{LoginDisabled, "User account disabled"}
var loginError = errors.New("internal server error")

type UserController struct {
	userStore UserStoreInterface
	mail      MailInterface
}

func NewUserController(userStore UserStoreInterface, mail MailInterface) UserController {
	return UserController{userStore, mail}
}

func (userController *UserController) CreateUser(email string, pass string) (user *datastore.User, err error) {

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
				return nil, loginError
			}
		}

		// Error in case of hash error
		return &loginFailure, nil
	}

	// Login if user exists and passwords match
	if (u != nil) && (hashErr == nil) {

		if u.Enabled == false {
			//TODO: handle disabled error
			return &loginDisabled, nil
		}

		if u.Activated == false {
			//TODO: handle un-activated error
			return &loginUnactivated, nil
		}

		if u.Locked == true {
			//TODO: handle locked error
			return &loginLocked, nil
		}

		if u.SecondFactors() == true {
			// Prompt for second factor login
			return &loginPartial, nil
		}

		//TODO: update login time etc.
		return &loginSuccess, nil
	}

	return &loginFailure, nil
}
