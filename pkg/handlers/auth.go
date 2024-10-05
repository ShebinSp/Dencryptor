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
			log.Println("No access token provided")
			http.Error(w, "Unauthorized entry, please login", http.StatusUnauthorized)
			return
		}

		tokenString := cookie.Value
		if tokenString == "" {
			log.Println("Empty token string")
			http.Error(w, "Unauthorized entry, please login", http.StatusUnauthorized)
			return
		}

		// Verify the token
		uid, err := auth.VerifyToken(tokenString)
		if err != nil {
			log.Println("Token verification failed:", err)
			http.Error(w, fmt.Sprintf("Token verification failed: %s", err.Error()), http.StatusUnauthorized)
			return
		}

		// Store the user ID in the request context
		ctx := context.WithValue(r.Context(), models.UserIDKey, uid)

		// Call the next handler with the new context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}


// Function to get userid from the coockie
func GetUserId(r *http.Request) (uint, bool) {
	id, ok := r.Context().Value(models.UserIDKey).(uint)
	fmt.Println("OK: ", ok)

	return id, ok
}
