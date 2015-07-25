// Basic authentication and authorisation for web tasks
package auth

import (
    "encoding/hex"
    "encoding/base64"

    // A vendored version of the golang bcrypt pkg
	"github.com/fragmenta/auth/internal/bcrypt"
)

// BCRYPT HASHES


// This should remain constant or hashed passwords will need to be recalculated
var HashCost = 10


// Compare a password hashed with bcrypt
func CheckPassword(plain_password, encrypted_password string) error {
	return bcrypt.CompareHashAndPassword([]byte(encrypted_password),[]byte(plain_password))
}


// Hash a password with a random salt using bcrypt.
func EncryptPassword(plain_password string) (string, error) {
    b,err := bcrypt.GenerateFromPassword([]byte(plain_password),HashCost)
	return string(b),err
}


// DEPRECATED - REMOVE BUT EXPERIMENT WITH EFFECT ON BOOKINGS FIRST

// Convert a hex string representation of bytes to a byte representation 
// (which may be unprintable)
func HexToBytes(h string) []byte {
    s,err := hex.DecodeString(h)
    if err != nil {
        s = []byte("ERROR")
    }
    return s
}

// Convert bytes to a hex string representation of bytes
func BytesToHex(b []byte) string {
    return hex.EncodeToString(b)
}



// ENCRYPTION




// TODO For CSRF below, we should include a time token at the end of the string
// and validate it is correct down to a given window (say 1 hour) - after that the token expires

// TODO http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/
// Encrypt Then Authenticate 
// The sender encrypts the plaintext, then appends a MAC of the ciphertext. Ek1(P) || MACk2(Ek1(P))

// TODO actually encrypt, don't just hash the CSRF

// Compare  plain text with a string encrypted by bcrypt as a csrf token
func CheckCSRFToken(plain_text, b64 string) error {
    // First base64 decode the value
    encrypted := make([]byte,256)
    _, err := base64.URLEncoding.Decode(encrypted,[]byte(b64))
    if err != nil {
        return err
    }
    
	return bcrypt.CompareHashAndPassword(encrypted,[]byte(plain_text))
}


// Encrypt a string with a random salt using bcrypt.
func CSRFToken(plain_text string) (string, error) {
    b,err := bcrypt.GenerateFromPassword([]byte(plain_text),HashCost)
    if err != nil {
        return "", err
    }
    
	return base64.URLEncoding.EncodeToString(b), nil
}


