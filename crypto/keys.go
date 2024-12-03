package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"sort"

	"github.com/yutianwu/chat-demo/logger"
)

// IdentityKey represents a long-term identity key pair
type IdentityKey struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// EphemeralKey represents a short-term ephemeral key pair
type EphemeralKey struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// SerializablePublicKey represents a public key that can be serialized to JSON
type SerializablePublicKey struct {
	X *big.Int
	Y *big.Int
}

// NewSerializablePublicKey creates a new SerializablePublicKey from an ECDSA public key
func NewSerializablePublicKey(pub *ecdsa.PublicKey) *SerializablePublicKey {
	return &SerializablePublicKey{
		X: pub.X,
		Y: pub.Y,
	}
}

// ToECDSA converts a SerializablePublicKey back to an ECDSA public key
func (s *SerializablePublicKey) ToECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     s.X,
		Y:     s.Y,
	}
}

// GenerateIdentityKey generates a new identity key pair
func GenerateIdentityKey() (*IdentityKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &IdentityKey{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// GenerateEphemeralKey generates a new ephemeral key pair
func GenerateEphemeralKey() (*EphemeralKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &EphemeralKey{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// calculateDH performs Diffie-Hellman key agreement
func calculateDH(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) []byte {
	// Convert ECDSA keys to ECDH keys
	privKey, err := ecdh.P256().NewPrivateKey(privateKey.D.Bytes())
	if err != nil {
		logger.Debug("Failed to create private ECDH key: %v", err)
		return nil
	}

	pubKey, err := ecdh.P256().NewPublicKey(publicKey.X.Bytes())
	if err != nil {
		logger.Debug("Failed to create public ECDH key: %v", err)
		return nil
	}

	// Perform ECDH key exchange
	sharedSecret, err := privKey.ECDH(pubKey)
	if err != nil {
		logger.Debug("ECDH key exchange failed: %v", err)
		return nil
	}

	logger.Debug("DH result: %s", hex.EncodeToString(sharedSecret))
	return sharedSecret
}

// KDF is a key derivation function using HMAC-SHA256
func KDF(input []byte) []byte {
	h := hmac.New(sha256.New, []byte("chain_key_derivation"))
	h.Write(input)
	result := h.Sum(nil)
	logger.Debug("KDF input: %s", hex.EncodeToString(input))
	logger.Debug("KDF output: %s", hex.EncodeToString(result))
	return result
}

// CalculateRootKey performs Triple DH and generates the root key
func CalculateRootKey(identity *IdentityKey, ephemeral *EphemeralKey,
	peerIdentityPub *ecdsa.PublicKey, peerEphemeralPub *ecdsa.PublicKey) []byte {
	logger.Debug("Calculating Triple DH")

	// DH1 = DH(IK_A, EK_B)
	logger.Debug("Calculating DH1")
	dh1 := calculateDH(identity.PrivateKey, peerEphemeralPub)

	// DH2 = DH(EK_A, IK_B)
	logger.Debug("Calculating DH2")
	dh2 := calculateDH(ephemeral.PrivateKey, peerIdentityPub)

	// DH3 = DH(EK_A, EK_B)
	logger.Debug("Calculating DH3")
	dh3 := calculateDH(ephemeral.PrivateKey, peerEphemeralPub)

	// Sort DH outputs to ensure consistent order
	dhOutputs := [][]byte{dh1, dh2, dh3}
	sort.Slice(dhOutputs, func(i, j int) bool {
		return bytes.Compare(dhOutputs[i], dhOutputs[j]) < 0
	})

	// Concatenate all DH outputs in sorted order
	combined := bytes.Join(dhOutputs, nil)
	logger.Debug("Combined DH results: %s", hex.EncodeToString(combined))

	// Generate root key
	return KDF(combined)
}

// DeriveChainKey derives the chain key from root key and salt
func DeriveChainKey(rootKey, salt []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(rootKey)
	result := h.Sum(nil)
	logger.Debug("Chain key derivation - Root key: %s", hex.EncodeToString(rootKey))
	logger.Debug("Chain key derivation - Salt: %s", hex.EncodeToString(salt))
	logger.Debug("Chain key derivation - Result: %s", hex.EncodeToString(result))
	return result
}

// RotateKeys generates new chain and message keys
func RotateKeys(chainKey []byte) (newChainKey, messageKey []byte) {
	// Generate message key
	h1 := hmac.New(sha256.New, []byte("message_key_seed"))
	h1.Write(chainKey)
	messageKey = h1.Sum(nil)

	// Generate new chain key
	h2 := hmac.New(sha256.New, []byte("chain_key_seed"))
	h2.Write(chainKey)
	newChainKey = h2.Sum(nil)

	logger.Debug("Key rotation - Old chain key: %s", hex.EncodeToString(chainKey))
	logger.Debug("Key rotation - New chain key: %s", hex.EncodeToString(newChainKey))
	logger.Debug("Key rotation - New message key: %s", hex.EncodeToString(messageKey))
	return
}

// Sign signs a message using the private key
func Sign(privateKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	// Concatenate r and s to create the signature
	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

// Verify verifies a signature using the public key
func Verify(publicKey *ecdsa.PublicKey, message []byte, signature []byte) bool {
	if len(signature) != 64 { // r and s should be 32 bytes each
		return false
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	hash := sha256.Sum256(message)
	return ecdsa.Verify(publicKey, hash[:], r, s)
}
