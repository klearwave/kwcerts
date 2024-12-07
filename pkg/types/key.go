package types

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/klearwave/kwcerts/pkg/utils"
)

const (
	Bits2048 KeyBits = 2048
	Bits4096 KeyBits = 4096
)

type KeyBits int

// key represents a generated certificate key object.
type key struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  rsa.PublicKey
}

// NewKey creates a new instance of a key object.
func NewKey() *key {
	return &key{}
}

// Generate generates the key.
func (k *key) Generate(bits KeyBits) error {
	// generate a new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, int(bits))
	if err != nil {
		return fmt.Errorf("error generating private key; %w", err)
	}

	k.PrivateKey = privateKey
	k.PublicKey = privateKey.PublicKey

	return nil
}

// Read reads a key from a given path.
func (k *key) Read(path string) error {
	privateKeyBytes, err := utils.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error private key file; %w", err)
	}

	block, _ := pem.Decode(privateKeyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("error decoding private key file; %w", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing private key file; %w", err)
	}

	k.PrivateKey = privateKey
	k.PublicKey = privateKey.PublicKey

	return nil
}

// Write writes key data to a file.
func (k *key) Write(keyPath string) error {
	// extract the private key content
	content, err := k.PrivateKeyBytes()
	if err != nil {
		return fmt.Errorf("error extracting private key content; %w", err)
	}

	return utils.WriteFile(keyPath, content)
}

// PrivateKeyBytes returns the private key bytes.
func (k *key) PrivateKeyBytes() ([]byte, error) {
	// encode the private key in PEM format
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k.PrivateKey),
	}), nil
}

// PublicKeyBytes returns the public key bytes.
func (k *key) PublicKeyBytes() ([]byte, error) {
	// convert the public key to DER-encoded PKIX format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("error marshaling public key; %w", err)
	}

	// encode the public key in PEM format
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}), nil
}

// IsValid determines if a KeyBits is valid.
func (bits KeyBits) IsValid() bool {
	for _, valid := range ValidKeyBits() {
		if bits == valid {
			return true
		}
	}

	return false
}

// ValidKeyBits is a maintained list of valid key bits.
func ValidKeyBits() []KeyBits {
	return []KeyBits{
		Bits2048,
		Bits4096,
	}
}
