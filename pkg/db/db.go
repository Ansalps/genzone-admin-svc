package db

import (
	"log"

	"github.com/Ansalps/genzone-admin-svc/pkg/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Handler struct {
	DB *gorm.DB
}

func Init(url string) Handler {
	db, err := gorm.Open(postgres.Open(url), &gorm.Config{})
	if err != nil {
		log.Fatalln(err)
	}
	db.AutoMigrate(&models.Admin{})
	return Handler{db}
}
