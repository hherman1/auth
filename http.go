package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"
)

type Authenticator interface {
	// Validates the given credentials and issues a login token for them if they are correct. Also returns the expiration date for the token.
	Authenticate(ctx context.Context, email, password string) (Token, time.Time, error)

	// Creates a new user with the given credentials
	Register(ctx context.Context, email, password string) error
}

type Validator interface {
	// Returns nil if the token represents a valid user account. Returns an error otherwise.
	Validate(context.Context, Token) error
}

type AuthFilter struct {
	Validator
	// Where to redirect if validation fails
	LoginURL string
}

// Wraps an existing handler to require a valid token as an argument to the handler. If there is no token, or an invalid token, set
// in the request, redirects to the login page and does not execute the handler function.
func (a AuthFilter) Handler(h func(Token, http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURL := fmt.Sprintf("%v?redirect=%v", a.LoginURL, url.QueryEscape(r.URL.String()))
		c, err := r.Cookie("auth_token")
		if err != nil {
			log.Printf("error: redirecting: reading auth_token cookie: %v", err)
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		var t Token
		err = t.UnmarshalText([]byte(c.Value))
		if err != nil {
			log.Printf("error: redirecting: parsing auth_token cookie: %v", err)
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		err = a.Validate(r.Context(), t)
		if err != nil {
			log.Printf("error: redirecting: invalid auth_token cookie: %v", err)
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		// success, call backing function
		h(t, w, r)
	})
}

// An auth server which handles login attempts and rendering the login page. This server provides handlers for a login page and a
// create user page, and supports redirects.
type AuthServer struct {
	Authenticator
}

// Returns an http handler that manages an auth subtree, adding pages for logging in, signing up, etc.
func (a AuthServer) Handler(prefix string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/login", http.HandlerFunc(a.loginPageHandler))
	mux.Handle("/signup", http.HandlerFunc(a.signupPageHandler))
	return http.StripPrefix(prefix, mux)
}

// Handle new users.
func (a AuthServer) signupPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Write([]byte(fmt.Sprintf(`
<html>
	<body>
		<h1> Sign Up </h1>
		<form action="signup?%v" method="post">
			<input name=email type=text placeholder="Email" />
			<input name=password type=password placeholder="Password" />
			<input type=submit />
		</form>
		<a href="login?%v"> Log In </a>
	</body>
</html>`, r.URL.RawQuery, r.URL.RawQuery)))
		return
	}
	if r.Method != "POST" {
		http.Error(w, fmt.Sprintf("invalid method: %v", r.Method), http.StatusBadRequest)
		return
	}

	// Validate
	err := r.ParseForm()
	if err != nil {
		http.Error(w, fmt.Sprintf("parse form: %v", err), http.StatusBadRequest)
		return
	}
	email := r.PostFormValue("email")
	password := r.PostFormValue("password")
	err = a.Register(r.Context(), email, password)
	if err != nil {
		http.Error(w, fmt.Sprintf("create user: %v", err), http.StatusBadRequest)
		return
	}
	a.loginPageHandler(w, r)
}

// We bind `login` as a GET to rendering the login page, and as a POST to assigning a token.
func (a AuthServer) loginPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Write([]byte(fmt.Sprintf(`
<html>
	<body>
		<h1> Login </h1>
		<form action="login?%v" method="post">
			<input name=email type=text placeholder="Email" />
			<input name=password type=password placeholder="Password" />
			<input type=submit />
		</form>
		<a href="signup?%v"> Sign Up </a>
	</body>
</html>`, r.URL.RawQuery, r.URL.RawQuery)))
		return
	}
	if r.Method != "POST" {
		http.Error(w, fmt.Sprintf("invalid method: %v", r.Method), http.StatusBadRequest)
		return
	}

	// Validate
	err := r.ParseForm()
	if err != nil {
		http.Error(w, fmt.Sprintf("parse form: %v", err), http.StatusBadRequest)
		return
	}
	email := r.PostFormValue("email")
	password := r.PostFormValue("password")
	t, expires, err := a.Authenticate(r.Context(), email, password)
	if errors.Is(err, errBadCredentials) {
		// We dont report the whole error to avoid returning info that could distinguish which credentials were bad
		http.Error(w, fmt.Sprintf("authenticate: %v", errBadCredentials), http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("authenticate: %v", err), http.StatusInternalServerError)
		return
	}
	// Success. Set cookie
	w.Header().Set("Set-Cookie", fmt.Sprintf("auth_token=%v; Expires=%v; Secure; Path=/", t, expires.Format(time.RFC3339)))
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}
