package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

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
