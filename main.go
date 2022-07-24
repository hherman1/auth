package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	_ "modernc.org/sqlite"
)

var clear = flag.Bool("clear", false, "TEST ONLY: Drops the database on start")
var logFlag = flag.Bool("v", false, "Enable verbose logging")
var dbfile = flag.String("f", "auth.sqlite", "DB file location")

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	flag.Parse()

	// Configure log
	if !*logFlag {
		log.SetOutput(io.Discard)
	}

	// Maybe clear the DB
	if *clear {
		err := os.Remove(*dbfile)
		if err != nil {
			return fmt.Errorf("-clear: remove %v: %w", *dbfile, err)
		}
	}

	db, err := sql.Open("sqlite", *dbfile)
	if err != nil {
		return fmt.Errorf("connect to SQLite3 DB: %w", err)
	}
	defer db.Close()

	// Create table
	err = initialize(ctx, db)
	if err != nil {
		return fmt.Errorf("initialize schema: %w", err)
	}

	err = RegisterUser(ctx, db, "hunter", "hunter@hherman.com", "test123")
	if err != nil {
		return fmt.Errorf("test user: %w", err)
	}

	// serve traffic
	auth := AuthServer{Authenticator: DBAuthenticator{db}}
	http.Handle("/auth/", auth.Handler("/auth"))
	filter := AuthFilter{
		Validator: DBAuthenticator{db},
		LoginURL:  "http://localhost:8090/auth/login",
	}
	http.Handle("/secured", filter.Handler(func(t Token, w http.ResponseWriter, r *http.Request) {
		w.Write(t[:])
	}))
	return http.ListenAndServe("localhost:8090", nil)
}
