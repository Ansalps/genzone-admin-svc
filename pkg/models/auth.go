package models

import "gorm.io/gorm"

type Admin struct {
	gorm.Model
	//ID       uint   `gorm:"primary key" json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
