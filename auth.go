// Package auth provides helpers for encryption, hashing and encoding.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	// A vendored version of the golang bcrypt pkg - we vendor mainly to avoid dependency on hg
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

// HexToBytes converts a hex string representation of bytes to a byte representation
func HexToBytes(h string) []byte {
	s, err := hex.DecodeString(h)
	if err != nil {
		s = []byte("")
	}
	return s
}

// BytesToHex converts bytes to a hex string representation of bytes
func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// Base64ToBytes converts from a b64 string to bytes
func Base64ToBytes(h string) []byte {
	s, err := base64.URLEncoding.DecodeString(h)
	if err != nil {
		s = []byte("")
	}
	return s
}

// BytesToBase64 converts bytes to a base64 string representation
func BytesToBase64(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}

// CreateMAC creates a MAC.
func CreateMAC(h hash.Hash, value []byte) []byte {
	h.Write(value)
	return h.Sum(nil)
}

// VerifyMAC verifies the MAC is valid with ConstantTimeCompare.
func VerifyMAC(h hash.Hash, value []byte, mac []byte) error {
	m := CreateMAC(h, value)
	if subtle.ConstantTimeCompare(mac, m) == 1 {
		return nil
	}
	return fmt.Errorf("Invalid MAC:%s", string(m))
}

// Encryption - based on gorrilla secure cookie

// Encrypt encrypts a value using the given key with AES.
func Encrypt(blockKey []byte, value []byte) ([]byte, error) {

	// Create cypher
	block, err := aes.NewCipher(blockKey)
	if err != nil {
		return nil, err
	}

	// A random initialization vector (http://goo.gl/zF67k) with the length of the
	// block size is prepended to the resulting ciphertext.
	iv := RandomToken(block.BlockSize())
	if iv == nil {
		return nil, errors.New("failed to generate random iv")
	}

	// Encrypt it.
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(value, value)

	// Return iv + ciphertext.
	return append(iv, value...), nil
}

// Decrypt decrypts a value using the given key with AES.
//
// The value to be decrypted must be prepended by a initialization vector
// (http://goo.gl/zF67k) with the length of the block size.
func Decrypt(blockKey []byte, value []byte) ([]byte, error) {

	block, err := aes.NewCipher(blockKey)
	if err != nil {
		return nil, err
	}

	size := block.BlockSize()
	if len(value) > size {
		// Extract iv.
		iv := value[:size]

		// Extract ciphertext.
		value = value[size:]

		// Decrypt it.
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(value, value)

		// Return on success
		return value, nil
	}

	return nil, errors.New("the value could not be decrypted")
}
