package usercontroller

//import "strings"
import "fmt"
import "log"
import "errors"
import "time"

import "golang.org/x/crypto/bcrypt"

import "github.com/ryankurte/authplz/datastore"

type UserStoreInterface interface {
	AddUser(email string, pass string) (user *datastore.User, err error)
	GetUserByExtId(extId string) (user *datastore.User, err error)
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
	tokenStore TokenStoreInterface
	mail      MailInterface
	hashRounds int
}

func NewUserController(userStore UserStoreInterface, tokenStore TokenStoreInterface, mail MailInterface) UserController {
	return UserController{userStore, tokenStore, mail, 8}
}

func (userController *UserController) Create(email string, pass string) (user *datastore.User, err error) {

	// Generate password hash
	hash, hashErr := bcrypt.GenerateFromPassword([]byte(pass), userController.hashRounds)
	if hashErr != nil {
		return nil, ErrorPasswordHashTooShort
	}

	// Check if user exists
	u, err := userController.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorFindingUser
	}

	if u != nil {
		// User exists, fail
		return nil, ErrorDuplicateAccount
	}

	// Add user to database (disabled)
	u, err = userController.userStore.AddUser(email, string(hash))
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorCreatingUser
	}

	// Generate user activation token

	// Generate user enrolment email from templates

	// Send account activation token to user email

	log.Printf("UserController.Create: User %s created\r\n", u.ExtId)

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

	log.Printf("UserController.Activate: User %s account activated\r\n", u.ExtId)

	return u, nil
}

func (userController *UserController) Unlock(email string) (user *datastore.User, err error) {

	// Fetch user account
	u, err := userController.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, loginError
	}

	u.Locked = false

	u, err = userController.userStore.UpdateUser(u)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, loginError
	}

	log.Printf("UserController.Unlock: User %s account unlocked\r\n", u.ExtId)

	return u, nil
}

//TODO: differentiate between login states and internal errors
func (userController *UserController) Login(email string, pass string) (status *LoginStatus, user *datastore.User, err error) {

	// Fetch user account
	u, err := userController.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
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

			if (u.LoginRetries > 5) && (u.Locked == false) {
				log.Printf("UserController.Login: Locking user %s", u.ExtId)
				u.Locked = true
			}

			u, err = userController.userStore.UpdateUser(u)
			if err != nil {
				// Userstore error, wrap
				log.Println(err)
				return nil, nil, loginError
			}

			log.Printf("UserController.Login: User %s login failed, invalid password\r\n", u.ExtId)
		} else {
			log.Printf("UserController.Login: Login failed, unrecognised account\r\n")
		}

		// Error in case of hash error
		return &LoginFailure, nil, nil
	}

	// Login if user exists and passwords match
	if (u != nil) && (hashErr == nil) {

		u.FidoTokens, _ = userController.tokenStore.GetFidoTokens(u)
		//TotpTokens, _ := userController.tokenStore.GetTotpTokens(u)

		if u.Enabled == false {
			//TODO: handle disabled error
			log.Printf("UserController.Login: User %s login failed, account disabled\r\n", u.ExtId)
			return &LoginDisabled, u, nil
		}

		if u.Activated == false {
			//TODO: handle un-activated error
			log.Printf("UserController.Login: User %s login failed, account deactivated\r\n", u.ExtId)
			return &LoginUnactivated, u, nil
		}

		if u.Locked == true {
			//TODO: handle locked error
			log.Printf("UserController.Login: User %s login failed, account locked\r\n", u.ExtId)
			return &LoginLocked, u, nil
		}

		if u.SecondFactors() == true {
			// Prompt for second factor login
			log.Printf("UserController.Login: User %s login failed, second factor required\r\n", u.ExtId)
			return &LoginPartial, u, nil
		}

		log.Printf("UserController.Login: User %s login successful\r\n", u.ExtId)

		// Update login time etc.
		u.LastLogin = time.Now()
		_, err = userController.userStore.UpdateUser(u)
		if err != nil {
			log.Println(err)
			return &LoginFailure, nil, nil
		}

		return &LoginSuccess, u, nil
	}

	return &LoginFailure, nil, nil
}

func (userController *UserController) GetUser(extId string) (user *datastore.User, err error) {
	// Attempt to fetch user
	u, err := userController.userStore.GetUserByExtId(extId)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorUserNotFound
	}

	return sanatizeUser(u), nil
}

func (userController *UserController) UpdatePassword(extId string, old string, new string) (user *datastore.User, err error) {

	// Fetch user
	u, err := userController.userStore.GetUserByExtId(extId)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorUserNotFound
	}

	// Check password
	hashErr := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(old))
	if hashErr != nil {
		return nil, ErrorPasswordMismatch
	}

	// Generate new hash
	hash, hashErr := bcrypt.GenerateFromPassword([]byte(new), userController.hashRounds)
	if hashErr != nil {
		return nil, ErrorPasswordHashTooShort
	}

	// Update user object
	u.Password = string(hash)
	u.PasswordChanged = time.Now()
	u, err = userController.userStore.UpdateUser(u)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorUpdatingUser
	}

	log.Printf("UserController.UpdatePassword: User %s password updated\r\n", extId)

	return sanatizeUser(u), nil
}



func (userController *UserController) AddFidoToken(extId string, token *datastore.FidoToken) (user *datastore.User, err error) {
	// Attempt to fetch user
	u, err := userController.userStore.GetUserByExtId(extId)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorUserNotFound
	}

	// Attempt to add tokens
	u, err = userController.tokenStore.AddFidoToken(u, token);
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorAddingToken
	}

	return sanatizeUser(u), nil
}

func (userController *UserController) GetFidoTokens(extId string) ([]datastore.FidoToken, error) {
		// Attempt to fetch user
	u, err := userController.userStore.GetUserByExtId(extId)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorUserNotFound
	}

	// Attempt to add tokens
	tokens, err := userController.tokenStore.GetFidoTokens(u);
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorAddingToken
	}

	return tokens, nil
}

func (userController *UserController) UpdateFidoToken(token datastore.FidoToken) error {


	return nil
}

// Internal function to remove non-public user fields prior to returning user objects
func sanatizeUser (u *datastore.User) *datastore.User {
	sanatizedUser := datastore.User{
		ExtId:	   u.ExtId,
		Email:     u.Email,
		Activated: u.Activated,
		Enabled:   u.Enabled,
		Locked:    u.Locked,
		Admin:     u.Admin,
		LastLogin: u.LastLogin,
	}
	return &sanatizedUser
}

