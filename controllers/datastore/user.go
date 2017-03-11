package datastore

import "time"
import "fmt"

import "github.com/jinzhu/gorm"

import "github.com/satori/go.uuid"
import "github.com/asaskevich/govalidator"

// User represents the user for this application
type User struct {
	ID              uint      `gorm:"primary_key" description:"External user ID"`
	CreatedAt       time.Time `description:"User creation time"`
	UpdatedAt       time.Time
	DeletedAt       *time.Time
	ExtID           string `gorm:"not null;unique"`
	Email           string `gorm:"not null;unique"`
	Username        string `gorm:"not null;unique"`
	Password        string `gorm:"not null"`
	PasswordChanged time.Time
	Activated       bool `gorm:"not null; default:false"`
	Enabled         bool `gorm:"not null; default:false"`
	Locked          bool `gorm:"not null; default:false"`
	Admin           bool `gorm:"not null; default:false"`
	LoginRetries    uint `gorm:"not null; default:0"`
	LastLogin       time.Time
	FidoTokens      []FidoToken
	TotpTokens      []TotpToken
	AuditEvents     []AuditEvent
}

// Getters and Setters

// GetExtID fetches a users ExtID
func (u *User) GetExtID() string { return u.ExtID }

// GetEmail fetches a users Email
func (u *User) GetEmail() string { return u.Email }

// GetUsername fetches a users Username
func (u *User) GetUsername() string { return u.Username }

// GetPassword fetches a users Password
func (u *User) GetPassword() string { return u.Password }

// GetPasswordChanged fetches a users PasswordChanged time
func (u *User) GetPasswordChanged() time.Time { return u.PasswordChanged }

// IsActivated checks if a user is activated
func (u *User) IsActivated() bool { return u.Activated }

// SetActivated sets a users activated status
func (u *User) SetActivated(activated bool) { u.Activated = activated }

// IsEnabled checks if a user is enabled
func (u *User) IsEnabled() bool { return u.Enabled }

// SetEnabled sets a users enabled status
func (u *User) SetEnabled(enabled bool) { u.Enabled = enabled }

// IsLocked checkes if a user account is locked
func (u *User) IsLocked() bool { return u.Locked }

// SetLocked sets a users locked status
func (u *User) SetLocked(locked bool) { u.Locked = locked }

// IsAdmin checks if a user is an admin
func (u *User) IsAdmin() bool { return u.Admin }

// SetAdmin sets a users admin status
func (u *User) SetAdmin(admin bool) { u.Admin = admin }

// GetLoginRetries fetches a users login retry count
func (u *User) GetLoginRetries() uint { return u.LoginRetries }

// SetLoginRetries sets a users login retry count
func (u *User) SetLoginRetries(retries uint) { u.LoginRetries = retries }

// ClearLoginRetries clears a users login retry count
func (u *User) ClearLoginRetries() { u.LoginRetries = 0 }

// GetLastLogin fetches a users LastLogin time
func (u *User) GetLastLogin() time.Time { return u.LastLogin }

// SetLastLogin sets a users LastLogin time
func (u *User) SetLastLogin(t time.Time) { u.LastLogin = t }

// SecondFactors Checks if a user has attached second factors
func (u *User) SecondFactors() bool {
	return (len(u.FidoTokens) > 0) || (len(u.TotpTokens) > 0)
}

// SetPassword sets a user password
func (u *User) SetPassword(pass string) {
	u.Password = pass
	u.PasswordChanged = time.Now()
}

// AddUser Adds a user to the datastore
func (dataStore *DataStore) AddUser(email, username, pass string) (interface{}, error) {

	if !govalidator.IsEmail(email) {
		return nil, fmt.Errorf("invalid email address %s", email)
	}

	user := &User{
		Email:     email,
		Username:  username,
		Password:  pass,
		ExtID:     uuid.NewV4().String(),
		Enabled:   true,
		Activated: false,
		Locked:    false,
		Admin:     false,
	}

	dataStore.db = dataStore.db.Create(user)
	err := dataStore.db.Error
	if err != nil {
		return nil, err
	}

	return user, nil
}

// GetUserByEmail Fetches a user account by email
func (dataStore *DataStore) GetUserByEmail(email string) (interface{}, error) {

	var user User
	err := dataStore.db.Where(&User{Email: email}).First(&user).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &user, nil
}

// GetUserByExtID Fetch a user account by external id
func (dataStore *DataStore) GetUserByExtID(extID string) (interface{}, error) {

	var user User
	err := dataStore.db.Where(&User{ExtID: extID}).First(&user).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &user, nil
}

// UpdateUser Update a user object
func (dataStore *DataStore) UpdateUser(user interface{}) (interface{}, error) {
	u := user.(*User)

	err := dataStore.db.Save(&u).Error
	if err != nil {
		return nil, err
	}

	return user, nil
}

// GetTokens Fetches tokens attached to a user account
func (dataStore *DataStore) GetTokens(user interface{}) (interface{}, error) {
	var err error

	u := user.(*User)

	err = dataStore.db.Model(user).Related(u.FidoTokens).Error
	if err != nil {
		return nil, err
	}
	err = dataStore.db.Model(user).Related(u.TotpTokens).Error
	if err != nil {
		return nil, err
	}

	return u, nil
}
