
package main

import "fmt"

import "github.com/jinzhu/gorm"
import _ "github.com/jinzhu/gorm/dialects/postgres"

type User struct {
  gorm.Model
  email string
  password string
  second_factors bool
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
    defer db.Close()

    db.AutoMigrate(&User{})

    return DataStore{db}
}

func (dataStore* DataStore) AddUser(email string, pass string) (user *User, err error) {

    return nil, nil
}

func (dataStore* DataStore) GetUserByUUID(uuid string) (user *User, err error) {

    return nil, nil
}

func (dataStore* DataStore) GetUserByEmail(email string) (user *User, err error) {

    return nil, nil
}
