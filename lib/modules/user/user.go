/*
 * User controller
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package user

import (
	"fmt"
	"log"
	"time"

	"github.com/nbutton23/zxcvbn-go"
	"golang.org/x/crypto/bcrypt"

	"github.com/authplz/authplz-core/lib/api"
	"github.com/authplz/authplz-core/lib/events"
)

const (
	// MinPasswordLength Minimum password length
	MinPasswordLength = 12
	// HashRounds BCrypt Hash Rounds
	HashRounds = 12
	// MinZxcvbnScore Minimum password zxcvbn score
	MinZxcvbnScore = 4
)

// Controller User controller instance storage
type Controller struct {
	userStore   Storer
	emitter     events.Emitter
	passwordLen int
	hashRounds  int
	zxcvbnScore int
}

// NewController Create a new user controller
func NewController(userStore Storer, emitter events.Emitter) *Controller {
	return &Controller{userStore, emitter, MinPasswordLength, HashRounds, MinZxcvbnScore}
}

// Create a new user account
func (userModule *Controller) Create(email, username, pass string) (user User, err error) {

	// Generate password hash
	hash, hashErr := bcrypt.GenerateFromPassword([]byte(pass), userModule.hashRounds)
	if hashErr != nil {
		return nil, ErrorPasswordHashTooShort
	}

	// Check length
	if len(pass) < userModule.passwordLen {
		return nil, ErrorPasswordTooShort
	}

	// Check complexity
	score := zxcvbn.PasswordStrength(pass, []string{email, username, "auth", "authplz"})
	if score.Score < userModule.zxcvbnScore {
		return nil, ErrorPasswordEntropyTooLow
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

	// Check if user exists
	u, err = userModule.userStore.GetUserByUsername(username)
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
	userModule.emitter.SendEvent(events.NewEvent(user.GetExtID(), events.AccountCreated, data))

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
	userModule.emitter.SendEvent(events.NewEvent(user.GetExtID(), events.AccountActivated, data))

	log.Printf("UserModule.Activate: User %s account activated\r\n", user.GetExtID())

	return user, nil
}

// Unlock unlocks the provided user account
func (userModule *Controller) Lock(email string) (user User, err error) {

	// Fetch user account
	u, err := userModule.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, errLogin
	}

	user = u.(User)

	user.SetLocked(true)

	u, err = userModule.userStore.UpdateUser(user)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, errLogin
	}

	user = u.(User)

	// Emit user unlock event
	data := make(map[string]string)
	userModule.emitter.SendEvent(events.NewEvent(user.GetExtID(), events.AccountLocked, data))

	log.Printf("UserModule.Unlock: User %s account locked\r\n", user.GetExtID())

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
	userModule.emitter.SendEvent(events.NewEvent(user.GetExtID(), events.AccountUnlocked, data))

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

				data := make(map[string]string)
				userModule.emitter.SendEvent(events.NewEvent(user.GetExtID(), events.AccountLocked, data))
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

// UserResp sanitised user object
type UserResp struct {
	ExtID     string
	Email     string
	Username  string
	Activated bool
	Enabled   bool
	Locked    bool
	LastLogin time.Time
	CreatedAt time.Time
}

func (ur *UserResp) GetExtID() string { return ur.ExtID }
func (ur *UserResp) GetEmail() string { return ur.Email }

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
	resp := UserResp{
		ExtID:     user.GetExtID(),
		Email:     user.GetEmail(),
		Username:  user.GetUsername(),
		Activated: user.IsActivated(),
		Enabled:   user.IsEnabled(),
		Locked:    user.IsLocked(),
		LastLogin: user.GetLastLogin(),
		CreatedAt: user.GetCreatedAt(),
	}

	return &resp, nil
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
	resp := UserResp{
		ExtID:     user.GetExtID(),
		Email:     user.GetEmail(),
		Username:  user.GetUsername(),
		Activated: user.IsActivated(),
		Enabled:   user.IsEnabled(),
		Locked:    user.IsLocked(),
		LastLogin: user.GetLastLogin(),
		CreatedAt: user.GetCreatedAt(),
	}

	return &resp, nil
}

func (userModule *Controller) handleSetPassword(user User, password string) error {

	// TODO: check password requirements here.
	// Not URL, Not in most common list, does not contain username or servicename

	// Generate new hash
	hash, err := bcrypt.GenerateFromPassword([]byte(password), userModule.hashRounds)
	if err != nil {
		return ErrorPasswordHashTooShort
	}

	// Check complexity
	score := zxcvbn.PasswordStrength(password, []string{user.GetEmail(), user.GetUsername(), "auth", "authplz"})
	if score.Score < userModule.zxcvbnScore {
		return ErrorPasswordEntropyTooLow
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
	userModule.emitter.SendEvent(events.NewEvent(user.GetExtID(), events.PasswordUpdate, data))

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
	if err != nil {
		return user, err
	}

	return user, nil
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
func (userModule *Controller) HandleToken(userid string, action api.TokenAction) (err error) {

	u, err := userModule.userStore.GetUserByExtID(userid)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return ErrorUserNotFound
	}

	if u == nil {
		log.Println("UpdatePassword error, user not found")
		return ErrorUserNotFound
	}

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
		userModule.emitter.SendEvent(events.NewEvent(user.GetExtID(), events.AccountNotEnabled, events.NewData()))
		log.Printf("UserModule.PreLogin: User %s login failed, account disabled\r\n", user.GetExtID())
		return false, nil
	}

	if user.IsActivated() == false {
		//TODO: handle un-activated error
		userModule.emitter.SendEvent(events.NewEvent(user.GetExtID(), events.AccountNotActivated, events.NewData()))
		log.Printf("UserModule.PreLogin: User %s login failed, account deactivated\r\n", user.GetExtID())
		return false, nil
	}

	if user.IsLocked() == true {
		//TODO: handle locked error
		userModule.emitter.SendEvent(events.NewEvent(user.GetExtID(), events.AccountNotUnlocked, events.NewData()))
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

	data := make(map[string]string)
	userModule.emitter.SendEvent(events.NewEvent(user.GetExtID(), events.LoginSuccess, data))

	return nil
}

// PostLoginFailure runs Failure actions for the user module
func (userModule *Controller) PostLoginFailure(u interface{}) error {
	user := u.(User)

	data := make(map[string]string)
	userModule.emitter.SendEvent(events.NewEvent(user.GetExtID(), events.LoginFailure, data))

	return nil
}
