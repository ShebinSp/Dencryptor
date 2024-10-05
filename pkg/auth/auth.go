package auth

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

var jwtKey = []byte(os.Getenv("SECRET"))

type JWTClaim struct {
	UserIDKey uint  `json:"useridkey"`
	Exp       int64 `json:"exp"`
	jwt.StandardClaims
}

func GenerateJWT(id uint) (string, error) {
	claims := &JWTClaim{
		UserIDKey: id,                                    // Set the user ID here
		Exp:       time.Now().Add(24 * time.Hour).Unix(), // Set expiration time
	}
	// log.Printf("User ID: %v ", claims.UserIDKey)
	// log.Printf("Generate Exp: %v ---- Type: %T", claims.Exp, claims.Exp)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// func VerifyToken(tokenString string) (uint, error) {
// 	claims := jwt.MapClaims{}
// 	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
// 		return jwtKey, nil
// 	})
// 	if err != nil {
// 		log.Println("The erorr is here in ParseWithClaims: ",err)
// 		return 0, err
// 	}

// 	claims, ok := token.Claims.(*JWTClaim)
// 	if !ok {
// 		err = errors.New("couldn't parse claims")
// 		return 0, err
// 	}

// 	if !token.Valid {
// 		return 0, fmt.Errorf("invalid token")
// 	}

// 	// geting user id
// 	id := claims.UserIDKey
// 	log.Println("got user id: ", id)

// 	// Check if the token is expired
// 	if claims.Exp < time.Now().Unix() {
// 		return 0, errors.New("token expired")
// 	}

// 	return id, nil
// }

func VerifyToken(tokenString string) (uint, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		log.Println("The error is here in ParseWithClaims: ", err)
		return 0, err
	}

	if !token.Valid {
		return 0, fmt.Errorf("invalid token")
	}

	// Extracting the user ID
	userIDKey, ok := claims["useridkey"].(float64) // JSON numbers are parsed as float64
	if !ok {
		return 0, errors.New("couldn't parse user ID")
	}

	id := uint(userIDKey)

	// Check if the token is expired
	exp, ok := claims["exp"].(float64) // JSON numbers are parsed as float64
	if !ok || int64(exp) < time.Now().Unix() {
		return 0, errors.New("token expired")
	}

	log.Println("got user id: ", id)
	return id, nil
}
