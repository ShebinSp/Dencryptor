package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ShebinSp/Dencryptor/pkg/config"
	"github.com/ShebinSp/Dencryptor/pkg/routes"
	"github.com/joho/godotenv"
)

var webPort = 8080

func main() {

	err := godotenv.Load("../../.env")
	if err != nil {
		log.Println("Error loading env: ",err)
	}

	// connect to db
	config.Config()

	mux := routes.RegisterRoutes()

	// server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", webPort),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	// Channel to listen for OS signals
	var sigchan = make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGABRT)

	go func() {
		log.Println("Server started on port :", 8080)
		// start the server
		log.Fatal(srv.ListenAndServe())
	}()

	// Wait for an interrupt signal
	sig := <-sigchan
	log.Println("Received signal: ",sig)

	// Shutdown the server gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 10 * time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Println("Server shutdown returned an error: ", err)
	}

	log.Println("Server shutdown gracefully")

}
