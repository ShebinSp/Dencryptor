package utils

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"strconv"
)

func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func Convert(str string) (uint, error) {
	id, err := strconv.Atoi(str)
	if err != nil {
		fmt.Println("Atoi Err: ", err)
		return 0, err
	}

	return uint(id), nil
}

func GetHash(id uint, hash string) string {
	idStr := fmt.Sprintf("%d", id)
	fmt.Println("Id in GetHash(): ", id)

	return hash + idStr
}

// Function to get userid from the coockie
func GetUserId(r *http.Request, key interface{}) (uint, bool) {
	id, ok := r.Context().Value(key).(uint)

	return id, ok
}

func GenerateFile() {

}
