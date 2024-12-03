package chat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/yutianwu/chat-demo/crypto"
	"github.com/yutianwu/chat-demo/logger"
)

// Session represents a secure chat session between two parties
type Session struct {
	ID                    string
	IdentityKey           *crypto.IdentityKey
	EphemeralKey          *crypto.EphemeralKey
	SendChainKey          []byte
	SendMsgKey            []byte
	RecvChainKey          []byte
	RecvMsgKey            []byte
	Salt                  []byte
	SendSeqNum            uint64
	RecvSeqNum            uint64
	mu                    sync.Mutex
	isKeyExchangeComplete bool
	isPeer                bool
	Username              string
}

// Message represents an encrypted chat message
type Message struct {
	ID        string `json:"id"`
	Sender    string `json:"sender"`
	Encrypted []byte `json:"encrypted"`
	SeqNum    uint64 `json:"seqnum"`
}

// SerializablePublicKey represents a serializable form of ecdsa.PublicKey
type SerializablePublicKey struct {
	X *big.Int `json:"x"`
	Y *big.Int `json:"y"`
}

// ToECDSA converts SerializablePublicKey to ecdsa.PublicKey
func (s *SerializablePublicKey) ToECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     s.X,
		Y:     s.Y,
	}
}

// FromECDSA converts ecdsa.PublicKey to SerializablePublicKey
func FromECDSA(pub *ecdsa.PublicKey) *SerializablePublicKey {
	return &SerializablePublicKey{
		X: pub.X,
		Y: pub.Y,
	}
}

// KeyExchange represents the key exchange message
type KeyExchange struct {
	IdentityPubKey  *crypto.SerializablePublicKey `json:"identity_pub_key"`
	EphemeralPubKey *crypto.SerializablePublicKey `json:"ephemeral_pub_key"`
	Salt           []byte                         `json:"salt"`
	Signature      []byte                         `json:"signature"`
}

// NewSession creates a new chat session
func NewSession(id string, username string) (*Session, error) {
	identityKey, err := crypto.GenerateIdentityKey()
	if err != nil {
		return nil, err
	}

	ephemeralKey, err := crypto.GenerateEphemeralKey()
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	return &Session{
		ID:                    id,
		IdentityKey:           identityKey,
		EphemeralKey:          ephemeralKey,
		Salt:                  salt,
		Username:              username,
		SendSeqNum:            0,
		RecvSeqNum:            0,
		isKeyExchangeComplete: false,
		isPeer:                false,
	}, nil
}

// SetPeer sets whether this session is the peer (Bob)
func (s *Session) SetPeer(isPeer bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isPeer = isPeer
}

// InitiateKeyExchange sends initial key exchange data
func (s *Session) InitiateKeyExchange() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create a key exchange message
	exchange := &KeyExchange{
		IdentityPubKey:  crypto.NewSerializablePublicKey(s.IdentityKey.PublicKey),
		EphemeralPubKey: crypto.NewSerializablePublicKey(s.EphemeralKey.PublicKey),
		Salt:           s.Salt,
	}

	// Create message to sign (concatenate public keys and salt)
	message := append([]byte{}, exchange.IdentityPubKey.X.Bytes()...)
	message = append(message, exchange.IdentityPubKey.Y.Bytes()...)
	message = append(message, exchange.EphemeralPubKey.X.Bytes()...)
	message = append(message, exchange.EphemeralPubKey.Y.Bytes()...)
	message = append(message, exchange.Salt...)

	// Sign the message with identity key
	signature, err := crypto.Sign(s.IdentityKey.PrivateKey, message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign key exchange: %v", err)
	}
	exchange.Signature = signature

	// Marshal the key exchange
	data, err := json.Marshal(exchange)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key exchange: %v", err)
	}

	logger.Debugf("Initiating key exchange - Identity X: %s", hex.EncodeToString(exchange.IdentityPubKey.X.Bytes()))
	logger.Debugf("Initiating key exchange - Identity Y: %s", hex.EncodeToString(exchange.IdentityPubKey.Y.Bytes()))

	return data, nil
}

// HandleKeyExchange processes received key exchange data
func (s *Session) HandleKeyExchange(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var exchange KeyExchange
	if err := json.Unmarshal(data, &exchange); err != nil {
		return fmt.Errorf("failed to unmarshal key exchange: %v", err)
	}

	// Verify the signature
	message := append([]byte{}, exchange.IdentityPubKey.X.Bytes()...)
	message = append(message, exchange.IdentityPubKey.Y.Bytes()...)
	message = append(message, exchange.EphemeralPubKey.X.Bytes()...)
	message = append(message, exchange.EphemeralPubKey.Y.Bytes()...)
	message = append(message, exchange.Salt...)

	if !crypto.Verify(exchange.IdentityPubKey.ToECDSA(), message, exchange.Signature) {
		return fmt.Errorf("invalid key exchange signature")
	}

	logger.Debugf("Received key exchange - Identity X: %s", hex.EncodeToString(exchange.IdentityPubKey.X.Bytes()))
	logger.Debugf("Received key exchange - Identity Y: %s", hex.EncodeToString(exchange.IdentityPubKey.Y.Bytes()))

	// Calculate root key using Triple DH
	rootKey := crypto.CalculateRootKey(
		s.IdentityKey,
		s.EphemeralKey,
		exchange.IdentityPubKey.ToECDSA(),
		exchange.EphemeralPubKey.ToECDSA(),
	)

	logger.Debugf("Root key: %s", hex.EncodeToString(rootKey))

	// Derive send and receive chain keys based on role
	if s.isPeer {
		// If we're Bob (peer), we use Alice's salt for sending and our salt for receiving
		s.SendChainKey = crypto.DeriveChainKey(rootKey, exchange.Salt)
		s.RecvChainKey = crypto.DeriveChainKey(rootKey, s.Salt)
	} else {
		// If we're Alice (initiator), we use our salt for sending and Bob's salt for receiving
		s.SendChainKey = crypto.DeriveChainKey(rootKey, s.Salt)
		s.RecvChainKey = crypto.DeriveChainKey(rootKey, exchange.Salt)
	}

	logger.Debugf("Send chain key: %s", hex.EncodeToString(s.SendChainKey))
	logger.Debugf("Recv chain key: %s", hex.EncodeToString(s.RecvChainKey))

	// Derive initial message keys
	s.SendMsgKey = crypto.KDF(s.SendChainKey)
	s.RecvMsgKey = crypto.KDF(s.RecvChainKey)

	logger.Debugf("Send msg key: %s", hex.EncodeToString(s.SendMsgKey))
	logger.Debugf("Recv msg key: %s", hex.EncodeToString(s.RecvMsgKey))

	s.isKeyExchangeComplete = true
	return nil
}

// SendMessage encrypts and prepares a message for sending
func (s *Session) SendMessage(content string) (*Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isKeyExchangeComplete {
		return nil, fmt.Errorf("key exchange not complete")
	}

	// Encrypt the message
	encrypted, err := crypto.Encrypt(s.SendMsgKey, []byte(content))
	if err != nil {
		return nil, err
	}

	logger.Debugf("Sending with msg key: %s", hex.EncodeToString(s.SendMsgKey))

	// Create message with sequence number
	msg := &Message{
		ID:        generateID(),
		Sender:    s.Username,
		Encrypted: encrypted,
		SeqNum:    s.SendSeqNum,
	}

	// Rotate keys for next message
	s.SendChainKey, s.SendMsgKey = crypto.RotateKeys(s.SendChainKey)
	s.SendSeqNum++

	return msg, nil
}

// ReceiveMessage decrypts a received message
func (s *Session) ReceiveMessage(msg *Message) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isKeyExchangeComplete {
		return "", "", fmt.Errorf("key exchange not complete")
	}

	// Verify sequence number
	if msg.SeqNum != s.RecvSeqNum {
		return "", "", fmt.Errorf("unexpected sequence number: got %d, want %d", msg.SeqNum, s.RecvSeqNum)
	}

	logger.Debugf("Receiving with msg key: %s", hex.EncodeToString(s.RecvMsgKey))

	// Decrypt the message
	decrypted, err := crypto.Decrypt(s.RecvMsgKey, msg.Encrypted)
	if err != nil {
		return "", "", err
	}

	// Rotate receive keys
	s.RecvChainKey, s.RecvMsgKey = crypto.RotateKeys(s.RecvChainKey)
	s.RecvSeqNum++

	return msg.Sender, string(decrypted), nil
}

// IsKeyExchangeComplete returns whether the key exchange is complete
func (s *Session) IsKeyExchangeComplete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isKeyExchangeComplete
}

// generateID generates a random session ID
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
