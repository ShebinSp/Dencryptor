package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/ShebinSp/Dencryptor/pkg/auth"
	"github.com/ShebinSp/Dencryptor/pkg/models"
)

// // Define a custom key to avoid context key collisions
// type contextKey string

// // Declare the custom key from user ID  storage
// const userIDKey = contextKey("userID")

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the Authorization cookie
		cookie, err := r.Cookie("Authorization")
		if err != nil {
			http.Error(w, "No access token provide, please login", http.StatusUnauthorized)
			return
		}
		log.Println("got cookie")

		tokenString := cookie.Value
		if tokenString == "" {
			http.Error(w, "No access token provide, please login", http.StatusUnauthorized)
			return
		}
		log.Println("tokenSTRING ok")

		// Verify the token
		uid, err := auth.VerifyToken(tokenString)
		if err != nil {
			http.Error(w, fmt.Sprintf("token verification failed: %s", err.Error()), http.StatusUnauthorized)
			return
		}
		log.Println("VerifyToken OK")

		// Store the user ID in the request context
		ctx := context.WithValue(r.Context(), models.UserIDKey, uid)

		// call the next handler with the new context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Function to get userid from the coockie
func HGetUserId(r *http.Request) (uint, bool) {
	id, ok := r.Context().Value(models.UserIDKey).(uint)
	fmt.Println("OK: ", ok)
	// cookie, err := r.Cookie("Authorization")
	// if err != nil {
	// 	return 0, false
	// }
	// id := cookie.Value
	// uid, err := Convert(id)
	// if err != nil {
	// 	fmt.Println("err : ", err)
	// }
	return id, ok
}
