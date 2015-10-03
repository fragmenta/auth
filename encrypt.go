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
)

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
