package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

type CryptoManager struct {
	encryptionKey []byte
	signingKey    ed25519.PrivateKey
	verifyKey     ed25519.PublicKey
}

func NewCryptoManager(encryptionKey []byte, signingKey ed25519.PrivateKey) (*CryptoManager, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes for AES-256")
	}

	if signingKey == nil {
		return nil, fmt.Errorf("signing key is required")
	}

	return &CryptoManager{
		encryptionKey: encryptionKey,
		signingKey:    signingKey,
		verifyKey:     signingKey.Public().(ed25519.PublicKey),
	}, nil
}

func GenerateEncryptionKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}
	return key, nil
}

func GenerateSigningKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate signing key pair: %w", err)
	}
	return privateKey, publicKey, nil
}

func (cm *CryptoManager) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(cm.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (cm *CryptoManager) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(cm.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func (cm *CryptoManager) Sign(data []byte) ([]byte, error) {
	signature := ed25519.Sign(cm.signingKey, data)
	return signature, nil
}

func (cm *CryptoManager) Verify(data []byte, signature []byte, publicKey ed25519.PublicKey) bool {
	if publicKey == nil {
		publicKey = cm.verifyKey
	}
	return ed25519.Verify(publicKey, data, signature)
}

func (cm *CryptoManager) Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

type SignedManifest struct {
	Data      []byte `json:"data"`
	Signature []byte `json:"signature"`
	Hash      string `json:"hash"`
	Timestamp int64  `json:"timestamp"`
}

func (cm *CryptoManager) CreateSignedManifest(data []byte, timestamp int64) (*SignedManifest, error) {
	hash := cm.Hash(data)
	signature, err := cm.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return &SignedManifest{
		Data:      data,
		Signature: signature,
		Hash:      hash,
		Timestamp: timestamp,
	}, nil
}

func (cm *CryptoManager) VerifyManifest(manifest *SignedManifest, publicKey ed25519.PublicKey) (bool, error) {
	hash := cm.Hash(manifest.Data)
	if hash != manifest.Hash {
		return false, fmt.Errorf("hash mismatch")
	}

	if !cm.Verify(manifest.Data, manifest.Signature, publicKey) {
		return false, fmt.Errorf("signature verification failed")
	}

	return true, nil
}

func EncryptFile(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func DecryptFile(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func HashData(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
