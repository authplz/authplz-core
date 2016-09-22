
package main

import "fmt"

import "github.com/satori/go.uuid"
import "github.com/asaskevich/govalidator"

import "github.com/jinzhu/gorm"
import _ "github.com/jinzhu/gorm/dialects/postgres"


type User struct {
  gorm.Model
  UUID string
  Email string
  Password string
  SecondFactors bool
}

type Token struct {
  gorm.Model
  user User
  userID int
  password string
  second_factors bool
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

  db.AutoMigrate(&User{})

  return DataStore{db}
}

func (dataStore* DataStore) Close() {
  dataStore.db.Close()  
}

func (dataStore* DataStore) AddUser(email string, pass string) (*User, error) {

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

func (dataStore* DataStore) GetUserByEmail(email string) (*User, error) {

  var user User

  err := dataStore.db.Where(&User{Email: email}).First(&user).Error
  if err != nil {
    return nil, err
  }

  return &user, nil
}

func (dataStore* DataStore) GetUserByUUID(uuid string) (*User, error) {

  var user User

  err := dataStore.db.Where(&User{UUID: uuid}).First(user).Error
  if err != nil {
    return nil, err
  }

  return &user, nil
}


