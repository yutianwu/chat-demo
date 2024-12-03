package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// Encrypt encrypts a message using AES-GCM with the provided message key
func Encrypt(messageKey, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(messageKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts a message using AES-GCM with the provided message key
func Decrypt(messageKey, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(messageKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aesGCM.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:aesGCM.NonceSize()]
	encryptedMsg := ciphertext[aesGCM.NonceSize():]

	plaintext, err := aesGCM.Open(nil, nonce, encryptedMsg, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
