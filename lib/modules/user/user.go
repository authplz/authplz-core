package user

import (
	"fmt"
	"log"
	"time"
)

import (
	"github.com/ryankurte/authplz/lib/api"
	"golang.org/x/crypto/bcrypt"
)

//TODO: change this to enforce actual complexity
const minimumPasswordLength = 12
const hashRounds = 8

// Controller User controller instance storage
type Controller struct {
	userStore  Storer
	emitter    api.EventEmitter
	hashRounds int
}

// NewController Create a new user controller
func NewController(userStore Storer, emitter api.EventEmitter) *Controller {
	return &Controller{userStore, emitter, hashRounds}
}

// Create a new user account
func (userModule *Controller) Create(email, username, pass string) (user User, err error) {

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
	u, err = userModule.userStore.AddUser(email, username, string(hash))
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorCreatingUser
	}

	user = u.(User)

	// Emit user creation event
	data := make(map[string]string)
	userModule.emitter.SendEvent(api.NewEvent(user, api.EventAccountCreated, data))

	log.Printf("UserModule.Create: User %s created\r\n", user.GetExtID())

	return user, nil
}

// Activate activates the provided user account
func (userModule *Controller) Activate(email string) (user User, err error) {

	// Fetch user account
	u, err := userModule.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		fmt.Println(err)
		return nil, errLogin
	}

	user = u.(User)

	user.SetActivated(true)

	u, err = userModule.userStore.UpdateUser(user)
	if err != nil {
		// Userstore error, wrap
		fmt.Println(err)
		return nil, errLogin
	}

	user = u.(User)

	// Emit user activation event
	data := make(map[string]string)
	userModule.emitter.SendEvent(api.NewEvent(user, api.EventAccountActivated, data))

	log.Printf("UserModule.Activate: User %s account activated\r\n", user.GetExtID())

	return user, nil
}

// Unlock unlocks the provided user account
func (userModule *Controller) Unlock(email string) (user User, err error) {

	// Fetch user account
	u, err := userModule.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, errLogin
	}

	user = u.(User)

	user.SetLocked(false)

	u, err = userModule.userStore.UpdateUser(user)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, errLogin
	}

	user = u.(User)

	// Emit user unlock event
	data := make(map[string]string)
	userModule.emitter.SendEvent(api.NewEvent(user, api.EventAccountUnlocked, data))

	log.Printf("UserModule.Unlock: User %s account unlocked\r\n", user.GetExtID())

	return user, nil
}

// Login checks user credentials and returns a login state and the associated user object (if found)
func (userModule *Controller) Login(email string, pass string) (bool, interface{}, error) {

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
		user := u.(User)
		hash = user.GetPassword()
	}

	// Generate password hash
	hashErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
	if hashErr != nil {
		if u != nil {
			user := u.(User)
			retries := user.GetLoginRetries()

			// Handle account lock after N retries
			user.SetLoginRetries(retries + 1)
			if (retries > 5) && (user.IsLocked() == false) {
				log.Printf("UserModule.Login: Locking user %s", user.GetExtID())
				user.SetLocked(true)
			}

			u, err = userModule.userStore.UpdateUser(user)
			if err != nil {
				// Userstore error, wrap
				log.Println(err)
				return false, nil, errLogin
			}

			log.Printf("UserModule.Login: User %s login failed, invalid password\r\n", user.GetExtID())
		} else {
			log.Printf("UserModule.Login: Login failed, unrecognised account\r\n")
		}

		// Error in case of hash error
		return false, nil, nil
	}

	// Login if user exists and passwords match
	if (u != nil) && (hashErr == nil) {
		user := u.(User)

		log.Printf("UserModule.Login: User %s login successful\r\n", user.GetExtID())

		return true, user, nil
	}

	return false, nil, nil
}

// GetUser finds a user by userID
func (userModule *Controller) GetUser(userid string) (interface{}, error) {
	// Attempt to fetch user
	u, err := userModule.userStore.GetUserByExtID(userid)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorUserNotFound
	}

	if u == nil {
		// Userstore error, wrap
		log.Printf("Error: user not found %s", userid)
		return nil, ErrorUserNotFound
	}

	user := u.(User)
	/*
		resp := UserResp{
			Email:     user.GetEmail(),
			Username:  user.GetUsername(),
			Activated: user.IsActivated(),
			Enabled:   user.IsEnabled(),
			Locked:    user.IsLocked(),
			LastLogin: user.GetLastLogin(),
		}
	*/
	return user, nil
}

// GetUserByEmail finds a user by userID
func (userModule *Controller) GetUserByEmail(email string) (interface{}, error) {
	// Attempt to fetch user
	u, err := userModule.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorUserNotFound
	}

	if u == nil {
		// Userstore error, wrap
		log.Printf("Error: user not found %s", email)
		return nil, ErrorUserNotFound
	}

	user := u.(User)
	/*
		resp := UserResp{
			Email:     user.GetEmail(),
			Username:  user.GetUsername(),
			Activated: user.IsActivated(),
			Enabled:   user.IsEnabled(),
			Locked:    user.IsLocked(),
			LastLogin: user.GetLastLogin(),
		}
	*/
	return user, nil
}

func (userModule *Controller) handleSetPassword(user User, password string) error {

	// TODO: check password requirements here.
	// Not URL, Not in most common list, does not contain username or servicename

	// Generate new hash
	hash, err := bcrypt.GenerateFromPassword([]byte(password), userModule.hashRounds)
	if err != nil {
		return ErrorPasswordHashTooShort
	}

	// Update user object
	user.SetPassword(string(hash))
	_, err = userModule.userStore.UpdateUser(user)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return ErrorUpdatingUser
	}

	// Emit password update event
	data := make(map[string]string)
	userModule.emitter.SendEvent(api.NewEvent(user, api.EventPasswordUpdate, data))

	// Log update
	log.Printf("UserModule.handleSetPassword: User %s password updated\r\n", user.GetExtID())

	return nil
}

// SetPassword sets a user password without checking the existing one
func (userModule *Controller) SetPassword(userid, password string) (User, error) {
	// Fetch user
	u, err := userModule.userStore.GetUserByExtID(userid)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorUserNotFound
	}

	if u == nil {
		log.Println("UserModule.SetPassword error, user not found")
		return nil, ErrorUserNotFound
	}

	user := u.(User)

	// Call password setting method
	err = userModule.handleSetPassword(user, password)

	return user, err
}

// UpdatePassword updates a user password
// This checks the original password prior to updating and fails on password errors
func (userModule *Controller) UpdatePassword(userid string, old string, new string) (User, error) {

	// Fetch user
	u, err := userModule.userStore.GetUserByExtID(userid)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorUserNotFound
	}

	if u == nil {
		log.Println("UpdatePassword error, user not found")
		return nil, ErrorUserNotFound
	}

	user := u.(User)

	// Check password
	hashErr := bcrypt.CompareHashAndPassword([]byte(user.GetPassword()), []byte(old))
	if hashErr != nil {
		return nil, ErrorPasswordMismatch
	}

	// Call password setting method
	err = userModule.handleSetPassword(user, new)

	return user, err
}

// HandleToken provides a generic method to handle an action token
// This executes the specified api.TokenAction on the provided user
func (userModule *Controller) HandleToken(u interface{}, action api.TokenAction) (err error) {

	user := u.(User)

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
func (userModule *Controller) PreLogin(u interface{}) (bool, error) {
	user := u.(User)

	if user.IsEnabled() == false {
		//TODO: handle disabled error
		log.Printf("UserModule.PreLogin: User %s login failed, account disabled\r\n", user.GetExtID())
		return false, nil
	}

	if user.IsActivated() == false {
		//TODO: handle un-activated error
		log.Printf("UserModule.PreLogin: User %s login failed, account deactivated\r\n", user.GetExtID())
		return false, nil
	}

	if user.IsLocked() == true {
		//TODO: handle locked error
		log.Printf("UserModule.PreLogin: User %s login failed, account locked\r\n", user.GetExtID())
		return false, nil
	}

	return true, nil
}

// PostLoginSuccess runs success actions for the user module
func (userModule *Controller) PostLoginSuccess(u interface{}) error {

	user := u.(User)

	// Update user object
	user.SetLastLogin(time.Now())
	_, err := userModule.userStore.UpdateUser(user)
	if err != nil {
		log.Printf("UserModule.PostLogin: error %s\r\n", err)
		return err
	}

	return nil
}

// PostLoginFailure runs Failure actions for the user module
func (userModule *Controller) PostLoginFailure(u interface{}) error {

	return nil
}
