package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
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
