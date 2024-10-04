package routes

import (
	"net/http"

	"github.com/ShebinSp/Dencryptor/pkg/handlers"
)

func RegisterRoutes() http.Handler {
	mux := http.NewServeMux()

	//	mux.HandleFunc("/", home)

	mux.HandleFunc("/user/signup", handlers.SignUpHandler)

	mux.HandleFunc("/user/login", handlers.LoginHandler)

	mux.Handle("/user/encrypt", handlers.AuthMiddleware(http.HandlerFunc(handlers.EncodeHandler)))

	mux.HandleFunc("/decrypt", handlers.DecodeHandler)

	mux.Handle("/user/getfiles", 
		handlers.AuthMiddleware(http.HandlerFunc(handlers.GetUserFilesHandler)))

	return mux
}
