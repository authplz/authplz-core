package datastore

import "time"

import "github.com/jinzhu/gorm"

// User object
type User struct {
	gorm.Model
	ExtId        string `gorm:"not null;unique"`
	Email        string `gorm:"not null;unique"`
	Password     string `gorm:"not null"`
	Activated    bool   `gorm:"not null; default:false"`
	Enabled      bool   `gorm:"not null; default:false"`
	Locked       bool   `gorm:"not null; default:false"`
	Admin        bool   `gorm:"not null; default:false"`
	LoginRetries uint   `gorm:"not null; default:0"`
	LastLogin    time.Time
	FidoTokens   []FidoToken
	TotpTokens   []TotpToken
	AuditEvents  []AuditEvent
}

func (u *User) SecondFactors() bool {
	return (len(u.FidoTokens) > 0) || (len(u.TotpTokens) > 0)
}

// It really frustrates me that I have to depend on the datastore.User type from usercontroller
// especially because the actual datastore can be an interface :-/

//type UserStoreInterface interface {
//    AddUser(email string, pass string) (user *datastore.User, err error)
//}

// The Go standard method seems to be to create a usercontroller user struct and include it in the database user struct
// However there does not seem to be a way to achieve this without requiring sql information / recursive inclusions :-/

// So I tried creating an interface and working with that, but it's also not a thing...
// It turns out you can't throw interfaces around as objects in the definition of interfaces
// Or, I can't work out how :-(
type UserInterface interface {
	GetExId() string
	GetEmail() string
	GetPassword() string
	SetPassword(pass string)
	GetActivated() bool
	SetActivated(activated bool)
	GetEnabled() bool
	SetEnabled(enabled bool)
	GetLocked() bool
	SetLocked(locked bool)
	GetAdmin() bool
	SetAdmin(admin bool)
	GetLoginRetries() uint
	ClearLoginRetries()
}

// Getters and Setters
func (u *User) GetExId() string             { return u.ExtId }
func (u *User) GetEmail() string            { return u.Email }
func (u *User) GetPassword() string         { return u.Password }
func (u *User) SetPassword(pass string)     { u.Password = pass }
func (u *User) GetActivated() bool          { return u.Activated }
func (u *User) SetActivated(activated bool) { u.Activated = activated }
func (u *User) GetEnabled() bool            { return u.Enabled }
func (u *User) SetEnabled(enabled bool)     { u.Enabled = enabled }
func (u *User) GetLocked() bool             { return u.Locked }
func (u *User) SetLocked(locked bool)       { u.Locked = locked }
func (u *User) GetAdmin() bool              { return u.Admin }
func (u *User) SetAdmin(admin bool)         { u.Admin = admin }
func (u *User) GetLoginRetries() uint       { return u.LoginRetries }
func (u *User) ClearLoginRetries()          { u.LoginRetries = 0 }
