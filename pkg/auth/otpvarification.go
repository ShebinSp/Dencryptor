package auth

import (
	"math/rand"
	"strconv"
	"time"
)

func GenerateOTP() string {
	seed := time.Now().UnixNano()
	randNumGen := rand.New(rand.NewSource(seed))

	return strconv.Itoa(randNumGen.Intn(8999) + 1000)
}