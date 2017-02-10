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
	ExtId           string `gorm:"not null;unique"`
	Email           string `gorm:"not null;unique"`
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
func (u *User) GetExtId() string            { return u.ExtId }
func (u *User) GetEmail() string            { return u.Email }
func (u *User) GetPassword() string         { return u.Password }
func (u *User) SetPassword(pass string)     { u.Password = pass }
func (u *User) IsActivated() bool           { return u.Activated }
func (u *User) SetActivated(activated bool) { u.Activated = activated }
func (u *User) IsEnabled() bool             { return u.Enabled }
func (u *User) SetEnabled(enabled bool)     { u.Enabled = enabled }
func (u *User) IsLocked() bool              { return u.Locked }
func (u *User) SetLocked(locked bool)       { u.Locked = locked }
func (u *User) IsAdmin() bool               { return u.Admin }
func (u *User) SetAdmin(admin bool)         { u.Admin = admin }
func (u *User) GetLoginRetries() uint       { return u.LoginRetries }
func (u *User) SetLoginRetries(retries uint){ u.LoginRetries = retries }
func (u *User) ClearLoginRetries()          { u.LoginRetries = 0 }

// Check if a user has attached second factors
func (u *User) SecondFactors() bool {
	return (len(u.FidoTokens) > 0) || (len(u.TotpTokens) > 0)
}

// Add a user to the datastore
func (dataStore *DataStore) AddUser(email string, pass string) (interface{}, error) {

	if !govalidator.IsEmail(email) {
		return nil, fmt.Errorf("invalid email address %s", email)
	}

	user := &User{
		Email:     email,
		Password:  pass,
		ExtId:     uuid.NewV4().String(),
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

// Fetch a user account by email
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

// Fetch a user account by external id
func (dataStore *DataStore) GetUserByExtId(extId string) (interface{}, error) {

	var user User
	err := dataStore.db.Where(&User{ExtId: extId}).First(&user).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &user, nil
}

// Update a user object
func (dataStore *DataStore) UpdateUser(user interface{}) (interface{}, error) {
	u := user.(*User)

	err := dataStore.db.Save(&u).Error
	if err != nil {
		return nil, err
	}

	return user, nil
}

// Fetch tokens attached to a user account
func (dataStore *DataStore) GetTokens(user interface{}) (interface{}, error) {
	var err error

	u := user.(*User)

	u.FidoTokens, err = dataStore.GetFidoTokens(u)
	u.TotpTokens, err = dataStore.GetTotpTokens(u)

	return u, err
}
