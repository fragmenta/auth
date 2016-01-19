package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	maxLength = 4096
	maxAge    = 86400 * 30
)

// These should be set once on app startup

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

// The session token key
var SessionTokenKey string

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
	SessionTokenKey = "authenticity_token"
}

// Session loads or create the current session
func Session(writer http.ResponseWriter, request *http.Request) (SessionStore, error) {

	s, err := SessionGet(request)
	if err != nil {
		// If no session, write it out for the first time (empty)
		//fmt.Printf("Error on cookie load: %s\n", err)
		s.Save(writer)
		return s, nil
	}

	return s, nil
}

// SessionGet loads the current session (if any)
func SessionGet(request *http.Request) (SessionStore, error) {

	// Return the current session store from cookie or a new one if none found
	s := &CookieSessionStore{
		values: make(map[string]string, 0),
	}

	if len(HMACKey) == 0 || len(SecretKey) == 0 || len(SessionTokenKey) == 0 {
		return s, errors.New("Authentication secrets not initialised")
	}

	// Check if the session exists and load it
	err := s.Load(request)
	if err != nil {
		return s, err // return blank session if none found
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

	cookie, err := request.Cookie(SessionName)
	if err != nil {
		return err
	}

	// Read the encrypted values back out into our values in the session
	err = s.Decode(SessionName, HMACKey, SecretKey, cookie.Value, &s.values)
	if err != nil {
		return err
	}

	return nil
}

// Save the session to a cookie
func (s *CookieSessionStore) Save(writer http.ResponseWriter) error {

	encrypted, err := s.Encode(SessionName, s.values, HMACKey, SecretKey)
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

// This code based on Gorilla secure cookie

// Encode a given value in the session cookie
func (s *CookieSessionStore) Encode(name string, value interface{}, hashKey []byte, blockKey []byte) (string, error) {

	if hashKey == nil || blockKey == nil {
		return "", errors.New("Keys not set")
	}

	// Serialize
	b, err := serialize(value)
	if err != nil {
		return "", err
	}

	// Encrypt with AES
	b, err = Encrypt(blockKey, b)
	if err != nil {
		return "", err
	}

	// Encode to base64
	b = encodeBase64(b)

	// Create MAC for "name|date|value". Extra pipe unused.
	now := time.Now().UTC().Unix()
	b = []byte(fmt.Sprintf("%s|%d|%s|", name, now, b))
	mac := CreateMAC(hmac.New(sha256.New, hashKey), b[:len(b)-1])

	// Append mac, remove name
	b = append(b, mac...)[len(name)+1:]

	// Encode to base64 again
	b = encodeBase64(b)

	// Check length when encoded
	if maxLength != 0 && len(b) > maxLength {
		return "", errors.New("Cookie: the value is too long")
	}

	// Done, convert to string and return
	return string(b), nil
}

// Decode the value in the session cookie
func (s *CookieSessionStore) Decode(name string, hashKey []byte, blockKey []byte, value string, dst interface{}) error {

	if hashKey == nil || blockKey == nil {
		return errors.New("Keys not set")
	}

	if maxLength != 0 && len(value) > maxLength {
		return errors.New("cookie value is too long")
	}

	// Decode from base64
	b, err := decodeBase64([]byte(value))
	if err != nil {
		return err
	}
	// Verify MAC - value is "date|value|mac"
	parts := bytes.SplitN(b, []byte("|"), 3)
	if len(parts) != 3 {
		return errors.New("MAC invalid")
	}
	h := hmac.New(sha256.New, hashKey)
	b = append([]byte(name+"|"), b[:len(b)-len(parts[2])-1]...)
	err = VerifyMAC(h, b, parts[2])
	if err != nil {
		return err
	}

	// Verify date ranges
	timestamp, err := strconv.ParseInt(string(parts[0]), 10, 64)
	if err != nil {
		return errors.New("timestamp invalid")
	}
	now := time.Now().UTC().Unix()
	if maxAge != 0 && timestamp < now-maxAge {
		return errors.New("timestamp expired")
	}

	// Decode from base64
	b, err = decodeBase64(parts[1])
	if err != nil {
		return err
	}

	// Derypt with AES
	b, err = Decrypt(blockKey, b)
	if err != nil {
		return err
	}

	// Deserialize
	err = deserialize(b, dst)
	if err != nil {
		return err
	}

	// Done.
	return nil
}

// encodeBase64 encodes a value using base64.
func encodeBase64(value []byte) []byte {
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(value)))
	base64.URLEncoding.Encode(encoded, value)
	return encoded
}

// decodeBase64 decodes a value using base64.
func decodeBase64(value []byte) ([]byte, error) {
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(value)))
	b, err := base64.URLEncoding.Decode(decoded, value)
	if err != nil {
		return nil, err
	}
	return decoded[:b], nil
}

// serialize encodes a value using gob.
func serialize(src interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(src); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// deserialize decodes a value using gob.
func deserialize(src []byte, dst interface{}) error {
	dec := gob.NewDecoder(bytes.NewBuffer(src))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}
