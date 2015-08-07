// Package auth provides helpers for encryption and passwords.
package auth

import (
	"errors"
	"fmt"
	"net/http"
	"time"
	// TODO - remove dependency as we don't use much of it
	"github.com/fragmenta/auth/internal/cookie"
)

// These should be set on app startup

// The key for generating HMAC
var HMACKey []byte

// The key for encrypting content
var SecretKey []byte

// The session name
var SessionName string

// Should we use secure cookies?
var SecureCookies bool

// The session user key
var SessionUserKey string

// SessionStore is the interface for a session store (backed by unknown storage)
type SessionStore interface {
	Get(string) string
	Set(string, string)
	Load(request *http.Request) error
	Save(http.ResponseWriter) error
	Clear(http.ResponseWriter)
}

// CookieSessionStore is a Concrete version of SessionStore, which stores the information encrypted with bcrypt in cookies.
type CookieSessionStore struct {
	values map[string]string
}

// init the package
func init() {
	// HttpOnly is on by default
	SecureCookies = false // off by default
	SessionName = "fragmenta_session"
	SessionUserKey = "user_id"
}

// Session loads or create the current session
func Session(writer http.ResponseWriter, request *http.Request) (SessionStore, error) {

	if len(HMACKey) == 0 || len(SecretKey) == 0 {
		return nil, errors.New("Authentication secrets not initialised")
	}

	// Return the current session store from cookie or a new one if none found
	s := &CookieSessionStore{
		values: make(map[string]string, 0),
	}

	// Check if the session exists
	err := s.Load(request)
	if err != nil {
		// If no session, write it out for the first time (empty)
		fmt.Printf("Error on cookie load: %s\n", err)
		s.Save(writer)
		return s, nil
	}

	return s, nil
}

// ClearSession clears the current session cookie
func ClearSession(writer http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   SessionName,
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	}

	http.SetCookie(writer, cookie)
}

// Get a value from the session
func (s *CookieSessionStore) Get(key string) string {
	return s.values[key]
}

// Set a value in the session - NB you must call Save after this if you wish to save
func (s *CookieSessionStore) Set(key string, value string) {
	s.values[key] = value
}

// Load the session from cookie
func (s *CookieSessionStore) Load(request *http.Request) error {

	// Just replace this with your own methods on CookieSessionStore...
	cookieMonster := cookie.New(HMACKey, SecretKey)

	cookie, err := request.Cookie(SessionName)
	if err != nil {
		return err
	}

	//  fmt.Printf("Cookie load: %v\n%v\n",err,cookie)

	// Read the encrypted values back out into our values in the session
	err = cookieMonster.Decode(SessionName, cookie.Value, &s.values)
	if err != nil {
		return err
	}

	return nil
}

// Save the session to a cookie
func (s *CookieSessionStore) Save(writer http.ResponseWriter) error {
	//  println("SAVING SESSION")

	// Just replace this with your own methods on CookieSessionStore...
	cookieMonster := cookie.New(HMACKey, SecretKey)

	encrypted, err := cookieMonster.Encode(SessionName, s.values)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     SessionName,
		Value:    encrypted,
		HttpOnly: true,
		Secure:   SecureCookies,
		Path:     "/",
		Expires:  time.Now().AddDate(0, 0, 7), // Expires in seven days

	}

	http.SetCookie(writer, cookie)

	return nil
}

// Clear the session values from the cookie
func (s *CookieSessionStore) Clear(writer http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   SessionName,
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	}

	http.SetCookie(writer, cookie)
}
