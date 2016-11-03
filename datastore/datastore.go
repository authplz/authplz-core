package datastore

import "fmt"
import "time"

import "github.com/satori/go.uuid"
import "github.com/asaskevich/govalidator"

import "github.com/jinzhu/gorm"
import _ "github.com/jinzhu/gorm/dialects/postgres"

// Fido/U2F token object
type FidoToken struct {
	gorm.Model
	UserID      uint
	Name        string
	KeyHandle   string
	PublicKey   string
	Certificate string
	Counter  	uint
	LastUsed time.Time
}

// Time based One Time Password Token object
type TotpToken struct {
	gorm.Model
	UserID     uint
	Name       string
	Secret     string
	UsageCount uint
	LastUsed time.Time
}

// Audit events for a login account
type AuditEvent struct {
	gorm.Model
	UserID    uint
	EventType string
	OriginIP  string
	ForwardedFor string
}

// Datastore instance storage
type DataStore struct {
	db *gorm.DB
}

// Query filter types
type QueryFilter struct {
	Limit  uint // Number of objects to return
	Offset uint // Offset of objects to return
}

func NewDataStore(dbString string) (*DataStore, error) {
	// Attempt database connection
	db, err := gorm.Open("postgres", dbString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect database: %s", dbString)
	}

	//db = db.LogMode(true)

	return &DataStore{db}, nil
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

	db = db.Model(&User{}).AddUniqueIndex("idx_user_email", "email")
	db = db.Model(&User{}).AddUniqueIndex("idx_user_ext_id", "ext_id")
}

func (dataStore *DataStore) AddUser(email string, pass string) (*User, error) {

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

func (dataStore *DataStore) GetUserByExtId(extId string) (*User, error) {

	var user User
	err := dataStore.db.Where(&User{ExtId: extId}).First(&user).Error
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

func (dataStore *DataStore) UpdateFidoToken(token *FidoToken) (*FidoToken, error) {

	err := dataStore.db.Save(&token).Error
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (ds *DataStore) AddAuditEvent(u *User, auditEvent *AuditEvent) (user *User, err error) {
	u.AuditEvents = append(u.AuditEvents, *auditEvent)
	u, err = ds.UpdateUser(u)
	return u, err
}

func (dataStore *DataStore) GetAuditEvents(u *User) ([]AuditEvent, error) {
	var auditEvents []AuditEvent

	err := dataStore.db.Model(u).Related(&auditEvents).Error

	return auditEvents, err
}
