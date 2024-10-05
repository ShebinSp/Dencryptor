package handlers

import (
	"net/http"

	"github.com/ShebinSp/Dencryptor/pkg/services"
	"github.com/ShebinSp/Dencryptor/pkg/users"
)

// type handler struct {}

// func(h *handler) ServeHTTP (w http.ResponseWriter, r *http.Client) error {

// 	return nil
// }

func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {

	case "POST":
		users.SignUp(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func VerificationHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		users.VerifyEmail(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		users.Login(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		users.Logout(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// func EncodeHandler(w http.ResponseWriter, r *http.Request) {
// 	switch r.Method {
// 	case "POST":
// 		services.EncodeImage(w, r)
// 	default:
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 	}
// }

func EncodeHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		services.EncodeImage(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func DecodeHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		services.DecodeImage(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func GetUserFilesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		users.GetUserFiles(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// func DownloadFileHandler(w http.ResponseWriter, r *http.Request){
// 	switch r.Method {
// 	case "GET":
// 		users.GetUserFiles(w, r)
// 	default:
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 	}
// }
