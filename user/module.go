package user

import (
	"fmt"
	"log"
	"time"
)

import (
	"github.com/ryankurte/authplz/token"
	"golang.org/x/crypto/bcrypt"
)

//TODO: change this to enforce actual complexity
const minimumPasswordLength = 12
const hashRounds = 8

type UserModule struct {
	userStore    UserStoreInterface
	tokenControl *token.TokenController
	hashRounds   int
}

func NewUserModule(userStore UserStoreInterface, tokenControl *token.TokenController) *UserModule {
	return &UserModule{userStore, tokenControl, hashRounds}
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

	// TODO: emit user creation event

	log.Printf("UserModule.Create: User %s created\r\n", user.GetExtId())

	return user, nil
}

func (userModule *UserModule) Activate(email string) (user UserInterface, err error) {

	// Fetch user account
	u, err := userModule.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		fmt.Println(err)
		return nil, loginError
	}

	user = u.(UserInterface)

	user.SetActivated(true)

	u, err = userModule.userStore.UpdateUser(user)
	if err != nil {
		// Userstore error, wrap
		fmt.Println(err)
		return nil, loginError
	}

	user = u.(UserInterface)

	log.Printf("UserModule.Activate: User %s account activated\r\n", user.GetExtId())

	return user, nil
}

func (userModule *UserModule) Unlock(email string) (user UserInterface, err error) {

	// Fetch user account
	u, err := userModule.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, loginError
	}

	user = u.(UserInterface)

	user.SetLocked(false)

	u, err = userModule.userStore.UpdateUser(user)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, loginError
	}

	user = u.(UserInterface)

	log.Printf("UserModule.Unlock: User %s account unlocked\r\n", user.GetExtId())

	return user, nil
}

//TODO: differentiate between login states and internal errors
func (userModule *UserModule) Login(email string, pass string) (*LoginStatus, UserInterface, error) {

	// Fetch user account
	u, err := userModule.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, nil, loginError
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
				return nil, nil, loginError
			}

			log.Printf("UserModule.Login: User %s login failed, invalid password\r\n", user.GetExtId())
		} else {
			log.Printf("UserModule.Login: Login failed, unrecognised account\r\n")
		}

		// Error in case of hash error
		return &LoginFailure, nil, nil
	}

	// Login if user exists and passwords match
	if (u != nil) && (hashErr == nil) {
		user := u.(UserInterface)

		//u.FidoTokens, _ = userModule.tokenStore.GetFidoTokens(u)
		//TotpTokens, _ := userModule.tokenStore.GetTotpTokens(u)

		if user.IsEnabled() == false {
			//TODO: handle disabled error
			log.Printf("UserModule.Login: User %s login failed, account disabled\r\n", user.GetExtId())
			return &LoginDisabled, user, nil
		}

		if user.IsActivated() == false {
			//TODO: handle un-activated error
			log.Printf("UserModule.Login: User %s login failed, account deactivated\r\n", user.GetExtId())
			return &LoginUnactivated, user, nil
		}

		if user.IsLocked() == true {
			//TODO: handle locked error
			log.Printf("UserModule.Login: User %s login failed, account locked\r\n", user.GetExtId())
			return &LoginLocked, user, nil
		}
		/*
			if u.SecondFactors() == true {
				// Prompt for second factor login
				log.Printf("UserModule.Login: User %s login failed, second factor required\r\n", u.GetExtId())
				return &LoginPartial, u, nil
			}
		*/
		log.Printf("UserModule.Login: User %s login successful\r\n", user.GetExtId())

		// Update login time etc.
		user.SetLastLogin(time.Now())
		_, err = userModule.userStore.UpdateUser(user)
		if err != nil {
			log.Println(err)
			return &LoginFailure, nil, nil
		}

		return &LoginSuccess, user, nil
	}

	return &LoginFailure, nil, nil
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

	log.Printf("UserModule.UpdatePassword: User %s password updated\r\n", extId)

	return user, nil
}
