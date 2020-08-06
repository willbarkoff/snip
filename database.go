package main

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func initializeDatabase() {
	var err error
	db, err = sql.Open("mysql", config.Database.Username+":"+config.Database.Password+"@/"+config.Database.Database+"?charset=utf8mb4&collation=utf8mb4_unicode_ci")
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
}

func deinitializeDatabase() {
	err := db.Close()
	if err != nil {
		panic(err)
	}
}
