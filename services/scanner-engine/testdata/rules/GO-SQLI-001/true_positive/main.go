package main

import (
	"database/sql"
	"os"
)

func main() {
	name := os.Getenv("USER")
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query(name)
}
