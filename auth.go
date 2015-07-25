// Package auth provides helpers for encryption and passwords.
package auth

import (
	"encoding/base64"

	// A vendored version of the golang bcrypt pkg
	"github.com/fragmenta/auth/internal/bcrypt"
)

// For bcrypt hashes - this should remain constant or hashed passwords will need to be recalculated
var HashCost = 10

// CheckPassword compares a password hashed with bcrypt
func CheckPassword(pass, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
}

// EncryptPassword hashes a password with a random salt using bcrypt.
func EncryptPassword(pass string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), HashCost)
	return string(hash), err
}

// TODO For CSRF below, we should include a time token at the end of the string
// and validate it is correct down to a given window (say 1 hour) - after that the token expires

// TODO http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/
// Encrypt Then Authenticate
// The sender encrypts the plaintext, then appends a MAC of the ciphertext. Ek1(P) || MACk2(Ek1(P))

// TODO actually encrypt, don't just hash the CSRF

// CheckCSRFToken compares a plain text with a string encrypted by bcrypt as a csrf token
func CheckCSRFToken(token, b64 string) error {
	// First base64 decode the value
	encrypted := make([]byte, 256)
	_, err := base64.URLEncoding.Decode(encrypted, []byte(b64))
	if err != nil {
		return err
	}

	return bcrypt.CompareHashAndPassword(encrypted, []byte(token))
}

// CSRFToken encrypts a string with a random salt using bcrypt.
func CSRFToken(token string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(token), HashCost)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}
