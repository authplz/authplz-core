package datastore

import "fmt"

import "github.com/satori/go.uuid"
import "github.com/asaskevich/govalidator"

import "github.com/jinzhu/gorm"
import _ "github.com/jinzhu/gorm/dialects/postgres"

// User object
type User struct {
	gorm.Model
	UUID         string `gorm:"not null;unique"`
	Email        string `gorm:"not null;unique"`
	Password     string `gorm:"not null"`
	Activated    bool   `gorm:"not null; default:false"`
	Enabled      bool   `gorm:"not null; default:false"`
	Locked       bool   `gorm:"not null; default:false"`
	Admin        bool   `gorm:"not null; default:false"`
	LoginRetries uint   `gorm:"not null; default:0"`
	FidoTokens   []FidoToken
	TotpTokens   []TotpToken
}

func (u *User) SecondFactors() bool {
	return (len(u.FidoTokens) > 0) || (len(u.TotpTokens) > 0)
}

// Fido/U2F token object
type FidoToken struct {
	gorm.Model
	UserID      uint
	Name        string
	KeyHandle   string
	PublicKey   string
	Certificate string
	UsageCount  uint
}

// Time based One Time Password Token object
type TotpToken struct {
	gorm.Model
	UserID     uint
	Name       string
	Secret     string
	UsageCount uint
}

// Audit events for a login account
type AuditEvent struct {
	gorm.Model
	UserID    uint
	EventType string
	OriginIP  string
}

type DataStore struct {
	db *gorm.DB
}

func NewDataStore(dbString string) (dataStore DataStore) {
	db, err := gorm.Open("postgres", dbString)
	if err != nil {
		fmt.Println("failed to connect database: " + dbString)
		panic(err)
	}

	db = db.LogMode(true)

	return DataStore{db}
}

func (dataStore *DataStore) Close() {
	dataStore.db.Close()
}

func (ds *DataStore) ForceSync() {
	db := ds.db

	db = db.Exec("DROP TABLE IF EXISTS fido_tokens CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS totp_tokens CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS audit_events CASCADE;")
	db = db.Exec("DROP TABLE IF EXISTS users CASCADE;")

	db = db.AutoMigrate(&User{})
	db = db.AutoMigrate(&FidoToken{})
	db = db.AutoMigrate(&TotpToken{})
	db = db.AutoMigrate(&AuditEvent{})
}

func (dataStore *DataStore) AddUser(email string, pass string) (*User, error) {

	if !govalidator.IsEmail(email) {
		return nil, fmt.Errorf("invalid email address %s", email)
	}

	user := &User{
		Email:     email,
		Password:  pass,
		UUID:      uuid.NewV4().String(),
		Enabled:   true,
		Activated: false,
		Locked:    false,
		Admin:     false}

	dataStore.db = dataStore.db.Create(user)
	err := dataStore.db.Error
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (dataStore *DataStore) GetUserByEmail(email string) (*User, error) {

	var user User
	err := dataStore.db.Where(&User{Email: email}).First(&user).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &user, nil
}

func (dataStore *DataStore) GetUserByUUID(uuid string) (*User, error) {

	var user User
	err := dataStore.db.Where(&User{UUID: uuid}).First(user).Error
	if (err != nil) && (err != gorm.ErrRecordNotFound) {
		return nil, err
	} else if (err != nil) && (err == gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &user, nil
}

func (dataStore *DataStore) UpdateUser(user *User) (*User, error) {

	err := dataStore.db.Save(&user).Error
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (ds *DataStore) AddFidoToken(u *User, fidoToken *FidoToken) (user *User, err error) {
	u.FidoTokens = append(u.FidoTokens, *fidoToken)
	u, err = ds.UpdateUser(u)
	return u, err
}

func (ds *DataStore) AddTotpToken(u *User, totpToken *TotpToken) (user *User, err error) {
	u.TotpTokens = append(u.TotpTokens, *totpToken)
	u, err = ds.UpdateUser(u)
	return u, err
}

func (dataStore *DataStore) GetFidoTokens(u *User) ([]FidoToken, error) {
	var fidoTokens []FidoToken

	err := dataStore.db.Model(u).Related(&fidoTokens).Error

	return fidoTokens, err
}

func (dataStore *DataStore) GetTotpTokens(u *User) ([]TotpToken, error) {
	var totpTokens []TotpToken

	err := dataStore.db.Model(u).Related(&totpTokens).Error

	return totpTokens, err
}

func (dataStore *DataStore) GetTokens(u *User) (*User, error) {
	var err error

	u.FidoTokens, err = dataStore.GetFidoTokens(u)
	u.TotpTokens, err = dataStore.GetTotpTokens(u)

	return u, err
}
