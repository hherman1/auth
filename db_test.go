package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestTokenGeneration(t *testing.T) {
	db := newDB(t, "token")
	ctx := context.Background()

	token, err := GenerateToken(ctx, db, "test", time.UnixMilli(0), time.UnixMilli(1000))
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	uid, err := Lookup(ctx, db, token, time.UnixMilli(500))
	if err != nil {
		t.Fatalf("lookup valid token: %v", err)
	}
	if uid != "test" {
		t.Fatalf("uid for valid token: expected 'test', was '%v'", uid)
	}
	// invalid token
	uid, err = Lookup(ctx, db, token, time.UnixMilli(5000))
	if err != errInvalidToken {
		t.Fatalf("expected invalid token error, got uid='%v', err='%v'", uid, err)
	}
}

func TestTokenReap(t *testing.T) {
	db := newDB(t, "token")
	ctx := context.Background()

	tokenOld, err := GenerateToken(ctx, db, "test", time.UnixMilli(0), time.UnixMilli(1000))
	if err != nil {
		t.Fatalf("generate tokenOld: %v", err)
	}
	tokenNew, err := GenerateToken(ctx, db, "test", time.UnixMilli(0), time.UnixMilli(2000))
	if err != nil {
		t.Fatalf("generate tokenNew: %v", err)
	}

	valid := func(name string, token Token, now time.Time) {
		uid, err := Lookup(ctx, db, token, now)
		if err != nil {
			t.Fatalf("lookup valid token: %v: %v", name, err)
		}
		if uid != "test" {
			t.Fatalf("uid for valid token: %v: expected 'test', was '%v'", name, uid)
		}
	}
	valid("old", tokenOld, time.UnixMilli(500))
	valid("new", tokenNew, time.UnixMilli(500))

	// Remove em
	err = ReapTokens(ctx, db, time.UnixMilli(1500))
	if err != nil {
		t.Fatalf("reaping: %v", err)
	}

	// new still exists
	valid("new", tokenNew, time.UnixMilli(500))

	// but old is gone
	uid, err := Lookup(ctx, db, tokenOld, time.UnixMilli(500))
	if err != errInvalidToken {
		t.Fatalf("expected invalid token error, got uid='%v', err='%v'", uid, err)
	}
}

func TestDuplicateUser(t *testing.T) {
	db := newDB(t, "user")
	ctx := context.Background()
	err := RegisterUser(ctx, db, "user1", "lol@localhost", "pw1")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	err = RegisterUser(ctx, db, "user1", "test@gmail.com", "pw1")
	if err == nil {
		t.Fatal("duplicate user ID succeeded")
	}
	err = RegisterUser(ctx, db, "user2", "lol@localhost", "pw1")
	if err == nil {
		t.Fatal("duplicate user Email succeeded")
	}
	err = RegisterUser(ctx, db, "user3", "looool@icloud.com", "pw1")
	if err != nil {
		t.Fatalf("register non duplicate user: %v", err)
	}
}

func TestAuth(t *testing.T) {
	db := newDB(t, "auth")
	ctx := context.Background()
	err := RegisterUser(ctx, db, "user1", "lol@localhost", "pw1")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	err = Authenticate(ctx, db, "user1", "pw1")
	if err != nil {
		t.Fatalf("username auth failed: %v", err)
	}
	err = Authenticate(ctx, db, "lol@localhost", "pw1")
	if err != nil {
		t.Fatalf("email auth failed: %v", err)
	}
	err = Authenticate(ctx, db, "lol@localhost", "pw2")
	if err == nil {
		t.Fatalf("email: bad password: succeeded")
	}
	err = Authenticate(ctx, db, "user1", "pw2")
	if err == nil {
		t.Fatalf("user: bad password: succeeded")
	}
	err = Authenticate(ctx, db, "fake", "pw2")
	if err == nil {
		t.Fatalf("fake id: succeeded")
	}
}

// Generates a new DB file in a temporary location, and creates all system tables
func newDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatalf("connect to SQLite3 DB '%v': %v", p, err)
	}
	err = initialize(context.Background(), db)
	if err != nil {
		t.Fatalf("initialize DB: %v", err)
	}
	return db
}
