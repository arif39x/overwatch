package main

import (
	"database/sql"
)

func main() {
	db, _ := sql.Open("sqlite3", ":memory:")
	db.Query("SELECT 1")
}
