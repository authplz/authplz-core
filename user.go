
package main

import "github.com/jinzhu/gorm"

type User struct {
  gorm.Model
  email string
  password string
  second_factors bool
}
