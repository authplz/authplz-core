package datastore

import "github.com/jinzhu/gorm"
import "github.com/ryankurte/authplz/usercontroller"

// User object
type User struct {
    gorm.Model
    usercontroller.User
    FidoTokens   []FidoToken
    TotpTokens   []TotpToken
}

func (u *User) SecondFactors() bool {
    return (len(u.FidoTokens) > 0) || (len(u.TotpTokens) > 0)
}

// Getters and Setters
// These are here because it appears to be the only way of generalising the user object using an interface
// The Go standard method would be to create a usercontroller user struct and include it in the database user struct
// However there does not seem to be a way to achieve this without requiring sql information 
func (u *User) GetUUID() string { return u.UUID }
func (u *User) GetEmail() string { return u.Email }
func (u *User) GetPassword() string { return u.Password }
func (u *User) SetPassword(pass string) { u.Password = pass }
func (u *User) GetActivated() bool { return u.Activated }
func (u *User) SetActivated(activated bool) { u.Activated = activated }
func (u *User) GetEnabled() bool { return u.Enabled }
func (u *User) SetEnabled(enabled bool) { u.Enabled = enabled }
func (u *User) GetLocked() bool { return u.Locked }
func (u *User) SetLocked(locked bool) { u.Locked = locked }
func (u *User) GetAdmin() bool { return u.Admin }
func (u *User) SetAdmin(admin bool) { u.Admin = admin }
func (u *User) GetLoginRetries() uint { return u.LoginRetries }
func (u *User) ClearLoginRetries() { u.LoginRetries = 0; }
