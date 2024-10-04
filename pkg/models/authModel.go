package models

// Define a custom key to avoid context key collisions
type ContextKey string
// Declare the custom key from user ID  storage
const UserIDKey = ContextKey("userID")

// OTP
type Otp struct {
	Email string `json:"email"`
	Otp string `json:"otp"`
}