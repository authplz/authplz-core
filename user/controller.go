package user

import(
	"fmt"
	"log"
	"time"
	)

import(
 	"golang.org/x/crypto/bcrypt"
 	"github.com/gocraft/web"
)


//TODO: change this to enforce actual complexity
const minimumPasswordLength = 12

type UserModule struct {
	userStore  UserStoreInterface
	hashRounds int
}

func NewUserModule(userStore UserStoreInterface) UserModule {
	return UserModule{userStore, 8}
}

func (userModule *UserModule) Bind(router *web.Router) {
	// Create router for user modules
	userRouter := router.Subrouter(UserApiCtx{}, "/api")

	// Attach middleware

	// Bind endpoints
	userRouter.Post("/create", (*UserApiCtx).Create)
}

// Create a new user account
func (userModule *UserModule) Create(email string, pass string) (user *User, err error) {

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

	// TODO: emit user creation event

	log.Printf("UserModule.Create: User %s created\r\n", u.GetId())

	return u, nil
}

func (userModule *UserModule) Activate(email string) (user *User, err error) {

	// Fetch user account
	u, err := userModule.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		fmt.Println(err)
		return nil, loginError
	}

	u.Activated = true

	u, err = userModule.userStore.UpdateUser(u)
	if err != nil {
		// Userstore error, wrap
		fmt.Println(err)
		return nil, loginError
	}

	log.Printf("UserModule.Activate: User %s account activated\r\n", u.GetId())

	return u, nil
}

func (userModule *UserModule) Unlock(email string) (user *User, err error) {

	// Fetch user account
	u, err := userModule.userStore.GetUserByEmail(email)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, loginError
	}

	u.Locked = false

	u, err = userModule.userStore.UpdateUser(u)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, loginError
	}

	log.Printf("UserModule.Unlock: User %s account unlocked\r\n", u.GetId())

	return u, nil
}

//TODO: differentiate between login states and internal errors
func (userModule *UserModule) Login(email string, pass string) (status *LoginStatus, user *User, err error) {

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
		hash = u.Password
	}

	// Generate password hash
	hashErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
	if hashErr != nil {

		if u != nil {
			u.LoginRetries++

			if (u.LoginRetries > 5) && (u.Locked == false) {
				log.Printf("UserModule.Login: Locking user %s", u.GetId())
				u.Locked = true
			}

			u, err = userModule.userStore.UpdateUser(u)
			if err != nil {
				// Userstore error, wrap
				log.Println(err)
				return nil, nil, loginError
			}

			log.Printf("UserModule.Login: User %s login failed, invalid password\r\n", u.GetId())
		} else {
			log.Printf("UserModule.Login: Login failed, unrecognised account\r\n")
		}

		// Error in case of hash error
		return &LoginFailure, nil, nil
	}

	// Login if user exists and passwords match
	if (u != nil) && (hashErr == nil) {

		u.FidoTokens, _ = userModule.tokenStore.GetFidoTokens(u)
		//TotpTokens, _ := userModule.tokenStore.GetTotpTokens(u)

		if u.Enabled == false {
			//TODO: handle disabled error
			log.Printf("UserModule.Login: User %s login failed, account disabled\r\n", u.GetId())
			return &LoginDisabled, u, nil
		}

		if u.Activated == false {
			//TODO: handle un-activated error
			log.Printf("UserModule.Login: User %s login failed, account deactivated\r\n", u.GetId())
			return &LoginUnactivated, u, nil
		}

		if u.Locked == true {
			//TODO: handle locked error
			log.Printf("UserModule.Login: User %s login failed, account locked\r\n", u.GetId())
			return &LoginLocked, u, nil
		}

		if u.SecondFactors() == true {
			// Prompt for second factor login
			log.Printf("UserModule.Login: User %s login failed, second factor required\r\n", u.GetId())
			return &LoginPartial, u, nil
		}

		log.Printf("UserModule.Login: User %s login successful\r\n", u.GetId())

		// Update login time etc.
		u.LastLogin = time.Now()
		_, err = userModule.userStore.UpdateUser(u)
		if err != nil {
			log.Println(err)
			return &LoginFailure, nil, nil
		}

		return &LoginSuccess, u, nil
	}

	return &LoginFailure, nil, nil
}

func (userModule *UserModule) GetUser(extId string) (user *User, err error) {
	// Attempt to fetch user
	u, err := userModule.userStore.GetUserByGetId()(extId)
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

	return sanatizeUser(u), nil
}

func (userModule *UserModule) UpdatePassword(extId string, old string, new string) (user *User, err error) {

	// Fetch user
	u, err := userModule.userStore.GetUserByGetId()(extId)
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
	hash, hashErr := bcrypt.GenerateFromPassword([]byte(new), userModule.hashRounds)
	if hashErr != nil {
		return nil, ErrorPasswordHashTooShort
	}

	// Update user object
	u.SetPassword(string(hash))
	u.SetPasswordChanged(time.Now())
	u, err = userModule.userStore.UpdateUser(u)
	if err != nil {
		// Userstore error, wrap
		log.Println(err)
		return nil, ErrorUpdatingUser
	}

	log.Printf("UserModule.UpdatePassword: User %s password updated\r\n", extId)

	return sanatizeUser(u), nil
}


// Internal function to remove non-public user fields prior to returning user objects
func sanatizeUser(u *User) *User {
	sanatizedUser := User{
		GetId():     u.GetId(),
		Email:     u.Email,
		Activated: u.Activated,
		Enabled:   u.Enabled,
		Locked:    u.Locked,
		Admin:     u.Admin,
		LastLogin: u.LastLogin,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
	return &sanatizedUser
}
