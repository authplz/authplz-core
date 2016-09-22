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
	FidoTokens   []FidoToken
	TotpTokens   []TotpToken
	LoginRetries uint
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

	//db.LogMode(true)

	db.AutoMigrate(&User{})
	db.AutoMigrate(&TotpToken{})
	db.AutoMigrate(&FidoToken{})
	db.AutoMigrate(&AuditEvent{})

	return DataStore{db}
}

func (dataStore *DataStore) Close() {
	dataStore.db.Close()
}

func (ds *DataStore) ForceSync() {
	ds.db.DropTableIfExists(&User{})
	ds.db.AutoMigrate(&User{})
	ds.db.DropTableIfExists(&FidoToken{})
	ds.db.AutoMigrate(&FidoToken{})
	ds.db.DropTableIfExists(&TotpToken{})
	ds.db.AutoMigrate(&TotpToken{})
	ds.db.DropTableIfExists(&AuditEvent{})
	ds.db.AutoMigrate(&AuditEvent{})
}

func (dataStore *DataStore) AddUser(email string, pass string) (*User, error) {

	if !govalidator.IsEmail(email) {
		return nil, fmt.Errorf("invalid email address %s", email)
	}

	user := &User{Email: email, Password: pass, UUID: uuid.NewV4().String()}

	err := dataStore.db.Create(user).Error
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

func (dataStore *DataStore) GetFidoTokens(u *User) ([]FidoToken, error) {
	var fidoTokens []FidoToken

	err := dataStore.db.Model(u).Related(&fidoTokens).Error

	return fidoTokens, err
}
