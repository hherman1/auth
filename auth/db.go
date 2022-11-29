package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Any valid connection type, e.g sql.DB, sql.Tx, sql.Conn.
type conn interface {
	// See sql.Conn for docs on these
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

//

// An implementation of authentication that uses the DB directly
type DBAuthenticator struct {
	db *sql.DB
}

func (d DBAuthenticator) Validate(ctx context.Context, t Token) error {
	_, err := Lookup(ctx, d.db, t, time.Now())
	if err != nil {
		return err
	}
	return nil
}
func (d DBAuthenticator) Register(ctx context.Context, email, password string) error {
	err := RegisterUser(ctx, d.db, email, email, password)
	if err != nil {
		return err
	}
	return nil
}

func (d DBAuthenticator) Authenticate(ctx context.Context, email, password string) (Token, time.Time, error) {
	expiration := time.Now().Add(24 * time.Hour)
	var t Token

	// Begin TX. We want token generation to occur in the same transaction as authentication
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return t, expiration, fmt.Errorf("open transaction: %w", err)
	}
	defer tx.Rollback()
	err = Authenticate(ctx, tx, email, password)
	if err != nil {
		return t, expiration, fmt.Errorf("authorization: %w", err)
	}
	uid, err := LookupByEmail(ctx, tx, email)
	if err != nil {
		return t, expiration, fmt.Errorf("lookup email: %w", err)
	}
	t, err = GenerateToken(ctx, tx, uid, time.Now().Add(-time.Second), expiration)
	if err != nil {
		return t, expiration, fmt.Errorf("generate token: %w", err)
	}
	err = tx.Commit()
	if err != nil {
		return t, expiration, fmt.Errorf("commit: %w", err)
	}
	return t, expiration, nil
}

// An authentication token which gives access priveleges for a certain time range.
type Token [16]byte

func (t Token) String() string {
	return base64.StdEncoding.EncodeToString(t[:])
}

func (t Token) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t *Token) UnmarshalText(text []byte) error {
	n, err := base64.StdEncoding.Decode(t[:], text)
	if err != nil {
		return fmt.Errorf("token: base64 decode: %w", err)
	}
	if n != 16 {
		return fmt.Errorf("token: expected 16 bytes, was %v", len(text))
	}
	return nil
}

// Drops all tokens from the DB which expired before the given time. It is recommended that an old time is used, not time.Now(), to manage clock jitter.
func ReapTokens(ctx context.Context, db conn, olderThan time.Time) error {
	_, err := db.ExecContext(ctx, `DELETE FROM TOKEN WHERE END_TIME < ?;`, olderThan.UnixMilli())
	if err != nil {
		return fmt.Errorf("drop rows: %w", err)
	}
	return nil
}

// Creates a new token, valid between the given times, for the given user, stores it, and returns it.
func GenerateToken(ctx context.Context, db conn, uid string, start, end time.Time) (Token, error) {
	// Make the token
	var t Token
	_, err := rand.Read(t[:])
	if err != nil {
		return t, fmt.Errorf("read random: %w", err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO TOKEN (UID, TOKEN, START_TIME, END_TIME)
	VALUES (?, ?, ?, ?);`,
		uid, t[:], start.UnixMilli(), end.UnixMilli())
	if err != nil {
		return t, fmt.Errorf("insert: %w", err)
	}
	return t, nil
}

// Find the user ID for the given email. Returns errBadCredentials if the email doesnt exist.
func LookupByEmail(ctx context.Context, db conn, email string) (string, error) {
	row := db.QueryRowContext(ctx, `SELECT ID FROM USER WHERE EMAIL=?`, email)
	var uid string
	err := row.Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errBadCredentials
	}
	if err != nil {
		return "", fmt.Errorf("parse uid: %w", err)
	}
	return uid, nil
}

var errInvalidToken = errors.New("invalid token")

// Finds the user ID of the associated USER for the given token, valid at the given time. If it is not a valid token, returns errInvalidToken.
func Lookup(ctx context.Context, db conn, t Token, now time.Time) (string, error) {
	row := db.QueryRowContext(ctx, `SELECT UID FROM TOKEN WHERE
TOKEN=? AND
START_TIME <= ? AND
END_TIME >= ?`, t[:], now.UnixMilli(), now.UnixMilli())
	var uid string
	err := row.Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errInvalidToken
	}
	if err != nil {
		return "", fmt.Errorf("parse uid: %w", err)
	}
	return uid, nil
}

// User functions

// Creates a new user. The ID and Email must not already exist. The email must be parsable as an email address.
func RegisterUser(ctx context.Context, db conn, id, email, password string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("parsing email address '%v': %w", email, err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash pw: %w", err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO USER(id, email, bcrypt) VALUES (?,?,?);`, id, email, hash)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

var errBadCredentials = errors.New("failed to authenticate, username or password is incorrect")

// Checks if these are valid credentials for a user. You should call this before issuing a token. Authenticating by
// ID or by email are both fine. If there is a problem with the credentials then errBadCredentials will be returned.
func Authenticate(ctx context.Context, db conn, idOrEmail, password string) error {
	row := db.QueryRowContext(ctx, `SELECT BCRYPT FROM USER WHERE
	ID = ? OR
	EMAIL = ?;`, idOrEmail, idOrEmail)

	var hash []byte
	err := row.Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return errBadCredentials
	}
	if err != nil {
		return fmt.Errorf("parse bcrypt: %w", err)
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return errBadCredentials
	}
	if err != nil {
		return fmt.Errorf("compare password to hash: %w", err)
	}
	return nil
}

// Ensures all our tables exist
func Initialize(ctx context.Context, db conn) error {
	steps := []struct {
		Name  string
		Query string
	}{
		{
			Name: "user",
			Query: `
CREATE TABLE IF NOT EXISTS USER (
	ID TEXT NOT NULL PRIMARY KEY,
	EMAIL TEXT NOT NULL UNIQUE,
	BCRYPT BLOB NOT NULL,
	VALID BOOLEAN DEFAULT FALSE NOT NULL
);`,
		},

		{
			Name: "token",
			Query: `
-- Tokens represent ephemeral access grants for a particular user. Currently tokens are randomly generated.
CREATE TABLE IF NOT EXISTS TOKEN (
	UID TEXT NOT NULL,
	TOKEN BLOB NOT NULL PRIMARY KEY,

	-- When this token is valid between.
	START_TIME INTEGER NOT NULL,
	END_TIME INTEGER NOT NULL,

	-- TODO: ACLs?

	FOREIGN KEY(UID) REFERENCES USER(ID)
);
		`,
		},
	}
	for _, step := range steps {
		_, err := db.ExecContext(ctx, step.Query)
		if err != nil {
			return fmt.Errorf("create tables: %v: %w", step.Name, err)
		}
	}

	return nil
}

// Shows all table schemas in the DB
func describeDB(ctx context.Context, db conn) error {
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name`)
	if err != nil {
		return fmt.Errorf("fetch tables: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		err = rows.Scan(&n)
		if err != nil {
			return fmt.Errorf("scan result: %w", err)
		}
		log.Println(n)
	}
	return nil
}
