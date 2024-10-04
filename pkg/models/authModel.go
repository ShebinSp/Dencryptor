package models

// Define a custom key to avoid context key collisions
type ContextKey string
// Declare the custom key from user ID  storage
const UserIDKey = ContextKey("userID")