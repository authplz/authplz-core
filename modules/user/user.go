package user

import (
	"errors"
	"fmt"
	"log"
	"time"
)

import (
	"github.com/ryankurte/authplz/api"
	"golang.org/x/crypto/bcrypt"
)

//TODO: change this to enforce actual complexity
const minimumPasswordLength = 12
const hashRounds = 8

var LoginError = errors.New("internal server error")

type UserModule struct {
	userStore  UserStoreInterface
	emitter    api.EventEmitter
	hashRounds int
}

func NewUserModule(userStore UserStoreInterface, emitter api.EventEmitter) *UserModule {
	return &UserModule{userStore, emitter, hashRounds}
}

// Create a new user account
func (userModule *UserModule) Create(email string, pass string) (user UserInterface, err error) {

	// Generate password hash
	hash, hashErr := bcrypt.GenerateFromPassword([]byte(pass), userModule.hashRounds)
	if hashErr != nil {
		return nil, ErrorPasswordHashTooShort
	}

	if len(pass) < minimumPasswordLength {
		return nil, ErrorPasswordTooShort
	}

	// Check if user exists
	u, err := userModule.userStore.GetUserByEmail(email)
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
	u, err = userModule.userStore.AddUser(email, string(hash))
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorCreatingUser
	}

	user = u.(UserInterface)

	// Emit user creation event
	data := make(map[string]string)
	userModule.emitter.SendEvent(api.NewEvent(user, api.EventAccountCreated, data))

	log.Printf("UserModule.Create: User %s created\r\n", user.GetExtId())

	return user, nil
}

func (userModule *UserModule) Activate(email string) (user UserInterface, err error) {

	// Fetch user account
	u, err := userModule.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		fmt.Println(err)
		return nil, LoginError
	}

	user = u.(UserInterface)

	user.SetActivated(true)

	u, err = userModule.userStore.UpdateUser(user)
	if err != nil {
		// Userstore error, wrap
		fmt.Println(err)
		return nil, LoginError
	}

	user = u.(UserInterface)

	// Emit user activation event
	data := make(map[string]string)
	userModule.emitter.SendEvent(api.NewEvent(user, api.EventAccountActivated, data))

	log.Printf("UserModule.Activate: User %s account activated\r\n", user.GetExtId())

	return user, nil
}

func (userModule *UserModule) Unlock(email string) (user UserInterface, err error) {

	// Fetch user account
	u, err := userModule.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, LoginError
	}

	user = u.(UserInterface)

	user.SetLocked(false)

	u, err = userModule.userStore.UpdateUser(user)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, LoginError
	}

	user = u.(UserInterface)

	// Emit user unlock event
	data := make(map[string]string)
	userModule.emitter.SendEvent(api.NewEvent(user, api.EventAccountUnlocked, data))

	log.Printf("UserModule.Unlock: User %s account unlocked\r\n", user.GetExtId())

	return user, nil
}

//TODO: differentiate between login states and internal errors
func (userModule *UserModule) Login(email string, pass string) (bool, interface{}, error) {

	// Fetch user account
	u, err := userModule.userStore.GetUserByEmail(email)
	if err != nil {
		log.Printf("UserModule.Login: error fetching user %s (%s)\r\n", email, err)
		return false, nil, nil
	}

	// Fake hash if user does not exist, then make login decision after
	// Avoids leaking account info by login timing
	hash := "fake password hash"
	if u != nil {
		user := u.(UserInterface)
		hash = user.GetPassword()
	}

	// Generate password hash
	hashErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
	if hashErr != nil {
		if u != nil {
			user := u.(UserInterface)
			retries := user.GetLoginRetries()

			// Handle account lock after N retries
			user.SetLoginRetries(retries + 1)
			if (retries > 5) && (user.IsLocked() == false) {
				log.Printf("UserModule.Login: Locking user %s", user.GetExtId())
				user.SetLocked(true)
			}

			u, err = userModule.userStore.UpdateUser(user)
			if err != nil {
				// Userstore error, wrap
				log.Println(err)
				return false, nil, LoginError
			}

			log.Printf("UserModule.Login: User %s login failed, invalid password\r\n", user.GetExtId())
		} else {
			log.Printf("UserModule.Login: Login failed, unrecognised account\r\n")
		}

		// Error in case of hash error
		return false, nil, nil
	}

	// Login if user exists and passwords match
	if (u != nil) && (hashErr == nil) {
		user := u.(UserInterface)

		log.Printf("UserModule.Login: User %s login successful\r\n", user.GetExtId())

		return true, user, nil
	}

	return false, nil, nil
}

func (userModule *UserModule) GetUser(extId string) (UserInterface, error) {
	// Attempt to fetch user
	u, err := userModule.userStore.GetUserByExtId(extId)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorUserNotFound
	}

	if u == nil {
		// Userstore error, wrap
		log.Printf("Error: user not found %s", extId)
		return nil, ErrorUserNotFound
	}

	return u.(UserInterface), nil
}

func (userModule *UserModule) UpdatePassword(extId string, old string, new string) (UserInterface, error) {

	// Fetch user
	u, err := userModule.userStore.GetUserByExtId(extId)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorUserNotFound
	}

	if u == nil {
		log.Println("UpdatePassword error, user not found")
		return nil, ErrorUserNotFound
	}

	user := u.(UserInterface)

	// Check password
	hashErr := bcrypt.CompareHashAndPassword([]byte(user.GetPassword()), []byte(old))
	if hashErr != nil {
		return nil, ErrorPasswordMismatch
	}

	// Generate new hash
	hash, hashErr := bcrypt.GenerateFromPassword([]byte(new), userModule.hashRounds)
	if hashErr != nil {
		return nil, ErrorPasswordHashTooShort
	}

	// Update user object
	user.SetPassword(string(hash))
	u, err = userModule.userStore.UpdateUser(user)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorUpdatingUser
	}

	// Emit password update event
	data := make(map[string]string)
	userModule.emitter.SendEvent(api.NewEvent(user, api.EventPasswordUpdate, data))

	log.Printf("UserModule.UpdatePassword: User %s password updated\r\n", extId)

	return user, nil
}

// Generic method to handle an action token
func (userModule *UserModule) HandleToken(u interface{}, action api.TokenAction) (err error) {

	user := u.(UserInterface)

	switch action {
	case api.TokenActionUnlock:
		log.Printf("UserModule.HandleToken: Unlocking user\n")
		userModule.Unlock(user.GetEmail())
		return nil

	case api.TokenActionActivate:
		log.Printf("UserModule.HandleToken: Activating user\n")
		userModule.Activate(user.GetEmail())
		return nil

	default:
		log.Printf("UserModule.HandleToken: Invalid token action\n")
		return api.TokenError
	}
}

// PreLogin checks for the user module
func (userModule *UserModule) PreLogin(u interface{}) (bool, error) {
	user := u.(UserInterface)

	if user.IsEnabled() == false {
		//TODO: handle disabled error
		log.Printf("UserModule.PreLogin: User %s login failed, account disabled\r\n", user.GetExtId())
		return false, nil
	}

	if user.IsActivated() == false {
		//TODO: handle un-activated error
		log.Printf("UserModule.PreLogin: User %s login failed, account deactivated\r\n", user.GetExtId())
		return false, nil
	}

	if user.IsLocked() == true {
		//TODO: handle locked error
		log.Printf("UserModule.PreLogin: User %s login failed, account locked\r\n", user.GetExtId())
		return false, nil
	}

	return true, nil
}

// PostLogin Success actions for the user module
func (userModule *UserModule) PostLoginSuccess(u interface{}) error {

	user := u.(UserInterface)

	// Update user object
	user.SetLastLogin(time.Now())
	_, err := userModule.userStore.UpdateUser(user)
	if err != nil {
		log.Printf("UserModule.PostLogin: error %s\r\n", err)
		return err
	}

	return nil
}

// PostLogin Failure actions for the user module
func (userModule *UserModule) PostLoginFailure(u interface{}) error {

	return nil
}
