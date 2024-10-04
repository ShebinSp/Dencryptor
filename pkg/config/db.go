package config

import (
	"fmt"
	"os"
	"sync"

	"github.com/ShebinSp/Dencryptor/pkg/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	db      *gorm.DB
	once    sync.Once
	initErr error
)

func Config() (*gorm.DB, error) {
	once.Do(func() {
		initErr = connectDb() // connect to db only once
	})
	if initErr != nil {
		return nil, initErr
	}

	return db, nil
}

func connectDb() error {
	var err error

	dsn := os.Getenv("dsn")
	if dsn == "" {
		return fmt.Errorf("DSN is not set in environment variables")
	}

	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := runMigration(); err != nil {
		return fmt.Errorf("failed to run migration: %v", err)
	}

	return nil
}

func runMigration() error {
	err := db.AutoMigrate(&models.ImageData{},
		&models.ImageFileList{},
		&models.User{})

	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	return nil
}
