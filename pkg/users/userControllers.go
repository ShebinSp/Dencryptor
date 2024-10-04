package users

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/ShebinSp/Dencryptor/pkg/auth"
	"github.com/ShebinSp/Dencryptor/pkg/config"
	"github.com/ShebinSp/Dencryptor/pkg/models"
	"github.com/ShebinSp/Dencryptor/pkg/utils"
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
)

var validate = validator.New()
var db *gorm.DB
var dbConnected = false

func connectToDb() error {
	dbConn, err := config.Config()
	if err != nil {
		return err
	}
	db = dbConn
	dbConnected = true
	return nil
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	var user models.User

	if !dbConnected {
		err := connectToDb()
		if err != nil {
			http.Error(w, "Database connection failed", http.StatusInternalServerError)
			return
		}
	}

	// Decode the JSON request
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if validationErr := validate.Struct(user); validationErr != nil {
		http.Error(w, validationErr.Error(), http.StatusBadRequest)
		return
	}

	if err = user.HashPassword(user.Password); err != nil {
		http.Error(w, "Please check the password requirements", http.StatusBadRequest)
		return
	}

	res := db.Table("users").Where("email = ?", user.Email)
	if res.RowsAffected != 0 {
		errMsg := fmt.Sprintf("%s Please login with email %s", "User email already exist\n", user.Email)

		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}

	res = db.Create(&user)
	if res.Error != nil {
		resp := map[string]string{
			"status": "false",
			"error":  "An error occured",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	if err := SendOTP(user.Email, r); err != nil {
		http.Error(w, "Email Verification failed", http.StatusBadRequest)
		return
	}

	ok := fmt.Sprintf("user '%s' registered, Please verify your email", user.FirstName)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ok)
}

func SendOTP(email string, r *http.Request) error {
	var user models.Otp

	otp := auth.GenerateOTP()
	user.Email = email
	user.Otp = otp

	res := db.Table("otps").Where("email = ?", email)
	if res.RowsAffected == 0 {
		res = db.Create(&user)
		if res.Error != nil {
			return fmt.Errorf("failed to create database: %v", res.Error)
		}
	} else if res.RowsAffected > 0 {
		res = db.Table("otps").Where("email = ?", user.Email).Update("otp", otp)
		if res.RowsAffected == 0 {
			//	errMsg := fmt.Sprintf("User with email \" %s \" does not exist, Please signup\n", user.Email)
			//	http.Error(w, errMsg, http.StatusBadRequest)
			return fmt.Errorf("user with email \" %s \" does not exist, Please signup", user.Email)
		}
		if res.Error != nil {
			//http.Error(w, res.Error.Error(), http.StatusBadRequest)
			return res.Error
		}
	} else {
		return res.Error
	}

	auth.SendEmail(email, "OTP Verification", []byte("Do not share OTP: "+otp), r)
	return nil
}

func VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var user models.Otp
	var svdInfo models.Otp

	// Decode the request body
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Failed to decode the data from request", http.StatusBadRequest)
		return
	}

	// Query the OTP based on email
	res := db.Table("otps").Where("email = ?", user.Email).Scan(&svdInfo)
	if res.RowsAffected == 0 {
		errMsg := fmt.Sprintf("User with email \" %s \" does not exist, Please signup\n", user.Email)
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	} else if res.Error != nil {
		http.Error(w, res.Error.Error(), http.StatusBadRequest)
		return
	}

	// Check if OTP matches
	if svdInfo.Otp != user.Otp {
		// If OTP doesn't match, delete the user and otp records
		rec := db.Table("users").Where("email = ?", user.Email).Delete(&models.User{})
		if rec.Error != nil {
			http.Error(w, "Error deleting user: "+rec.Error.Error(), http.StatusInternalServerError)
			return
		}

		res := db.Table("otps").Where("email = ?", user.Email).Delete(&models.Otp{})
		if res.Error != nil {
			http.Error(w, "Error deleting OTP: "+res.Error.Error(), http.StatusInternalServerError)
			return
		}

		http.Error(w, "Invalid OTP", http.StatusBadRequest)
		return
	}

	// If OTP is correct, update the OTP field to "ok"
	res = db.Table("otps").Where("email = ?", user.Email).Update("otp", "ok")
	if res.Error != nil {
		http.Error(w, "OTP updation failed", http.StatusInternalServerError)
		return
	}

	// Send success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]string{"message": "OTP verified, Please login"}
	json.NewEncoder(w).Encode(response)
}

func Login(w http.ResponseWriter, r *http.Request) {

	type userInfo struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var userinfo userInfo
	var user models.User
	var otp string

	if !dbConnected {
		err := connectToDb()
		if err != nil {
			http.Error(w, "failed to establish database connection", http.StatusBadRequest)
		}
	}

	// Decode the JSON request
	err := json.NewDecoder(r.Body).Decode(&userinfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Println("Decoded user data:", userinfo.Email)
	log.Println("user otp in login: ", otp)

	// Retrieve OTP from the database
	res := db.Table("otps").Where("email = ?", userinfo.Email).Select("otp").Scan(&otp)

	// If no record is found, delete the user and return an error
	if res.RowsAffected == 0 {
		rec := db.Table("users").Where("email = ?", userinfo.Email).Delete(&models.User{})
		if rec.Error != nil {
			http.Error(w, "an error occurred while deleting user: "+rec.Error.Error(), http.StatusInternalServerError)
			return
		}
		http.Error(w, "User not verified", http.StatusBadRequest)
		return
	}

	// Handle any error that occurred while retrieving the OTP
	if res.Error != nil {
		http.Error(w, "an error occurred while retrieving OTP: "+res.Error.Error(), http.StatusInternalServerError)
		return
	}

	// If the OTP is not "ok", delete the user and return an error
	if otp != "ok" {
		rec := db.Table("users").Where("email = ?", userinfo.Email).Delete(&models.User{})
		if rec.Error != nil {
			http.Error(w, "an error occurred while deleting user: "+rec.Error.Error(), http.StatusInternalServerError)
			return
		}
		http.Error(w, "User not verified", http.StatusBadRequest)
		return
	}

	// Query the user email
	rec := db.Table("users").Where("email = ?", userinfo.Email).Scan(&user)
	if rec.Error != nil {
		http.Error(w, "user does not exit", http.StatusBadRequest)
		return
	}
	// Check if the user existed
	if rec.RowsAffected == 0 {
		http.Error(w, "User does not exist", http.StatusBadRequest)
		return
	}

	passwordOk, err := user.VerifyPassword(userinfo.Password)
	if err != nil {
		http.Error(w, fmt.Sprintf("an error occured: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	if !passwordOk {
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}

	token, err := auth.GenerateJWT(user.Id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set Samesite and other cookie options
	cookie := &http.Cookie{
		Name:     "Authorization",
		Value:    token,
		Path:     "/",
		MaxAge:   3600 * 24,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}

	// Set the cookie in the response header
	http.SetCookie(w, cookie)

	// Return a success message in JSON format
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	// json.NewEncoder(w).Encode(map[string]string{
	// 	"message": "You are successfully logged in",
	// })
	json.NewEncoder(w).Encode("You are successfully logged in")
}

// Function to get all user image files
func GetUserFiles(w http.ResponseWriter, r *http.Request) {
	var imgLst []models.ImageFileList

	type imgList struct {
		Id       uint
		FileName string
		Hash     string
	}

	if !dbConnected {
		err := connectToDb()
		if err != nil {
			http.Error(w, "failed to establish database connection", http.StatusBadRequest)
			return
		}
	}

	id, ok := utils.GetUserId(r, models.UserIDKey)
	if !ok {
		http.Error(w, "An error occured, please login again", http.StatusInternalServerError)
		return
	}

	res := db.Table("image_file_lists").Where("user_id = ?", id).Scan(&imgLst)
	if res.RowsAffected == 0 {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Assigning file info to field
	var imglst []imgList
	for _, img := range imgLst {
		imglst = append(imglst, imgList{
			Id:       img.Id,
			FileName: img.FileName,
			Hash:     img.Hash,
		})
	}

	// iL.Id = imgLst.Id
	// iL.FileName = imgLst.FileName
	// iL.Hash = imgLst.Hash

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"imageList": imglst,
	})

}
