package auth

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

/* These DEPRECATED functions should not be used and will be removed in next minor version */

// CheckCSRFToken DEPRECATED
func CheckCSRFToken(token, b64 string) error {
	// First base64 decode the value
	encrypted := make([]byte, 256)
	_, err := base64.URLEncoding.Decode(encrypted, []byte(b64))
	if err != nil {
		return err
	}

	return bcrypt.CompareHashAndPassword(encrypted, []byte(token))
}

// CSRFToken DEPRECATED
func CSRFToken(token string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(token), HashCost)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

// EncryptPassword DEPRECATED  - renamed to HashPassword to be clearer
func EncryptPassword(pass string) (string, error) {
	fmt.Printf("Please use HashPassword instead, auth.EncryptPassword is deprecated")
	return HashPassword(pass)
}
