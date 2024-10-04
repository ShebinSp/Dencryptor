package models

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	Id        uint `gorm:"primarykey;unique"`
	Email     string `json:"email" gorm:"not null;unique"`
	Password  string `json:"password" gorm:"not null"`
	FirstName string `json:"first_name" gorm:"not null"`
	LastName  string `json:"last_name" gorm:"not null"`
	Age       int    `json:"age" gorm:"not null"`
	Country   string `json:"country" gorm:"not null"`
}

func (user *User) HashPassword(password string) error {
	passbyte, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return err
	}

	user.Password = string(passbyte)
	return nil
}

func (user *User) VerifyPassword(password string) (bool, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return false, err
	}
	return true, nil
}

func GetUserEmail(id uint, db *gorm.DB) (string, error) {
	var result struct {
		Email string
	}

	//res := db.Table("users").Where("id = ?", id).Select("email").Scan(&userEmail)
	res := db.Table("users").Where("id = ?", id).Select("email").First(&result)
	if res.RowsAffected == 0 {
		return "", fmt.Errorf("user with ID %d not found", id)
	}
	if res.Error != nil {
		return "", fmt.Errorf("error retrieving user email: %w", res.Error)
	}

	return result.Email, nil

}


