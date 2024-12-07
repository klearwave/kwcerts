package types

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/klearwave/kwcerts/pkg/utils"
)

// certificate represents a generated certificate object.
type certificate struct {
	CertificateData []byte
	Request         *x509.Certificate
}

// NewCertificate creates a new instance of a certificate object.
func NewCertificate() *certificate {
	return &certificate{}
}

// Read reads a certificate from a given path.
func (cert *certificate) Read(path string) error {
	// read the certificate file
	certBytes, err := utils.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error reading file; %w", err)
	}

	// decode the PEM block
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("error decoding certificate contents; %w", err)
	}

	cert.CertificateData = block.Bytes

	return nil
}

// SetRequest sets the request on a certificate object.
func (c *certificate) SetRequest(request *x509.Certificate) {
	c.Request = request
}

// Generate generates a new certificate from a certificate authority object.
func (c *certificate) Generate(k *key, ca *certificateAuthority) error {
	// create the new certificate signed by the CA
	certBytes, err := x509.CreateCertificate(rand.Reader, c.Request, ca.Certificate.Request, k.PublicKey, ca.Key.PrivateKey)
	if err != nil {
		fmt.Printf("Error creating certificate: %v\n", err)
		return
	}

	// Encode the new certificate to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
}

// Object returns an upstream x509 certificate object from the data stored.
func (c *certificate) Object() (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(c.CertificateData)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate contents; %w", err)
	}

	return cert, nil
}

// Print prints the certificate information similar to what the popular command
// openssl x509 -in cert.vrt -noout -text provides.
func (c *certificate) Print() error {
	object, err := c.Object()
	if err != nil {
		return fmt.Errorf("error retrieving x509.Certificate object; %w", err)
	}

	// output certificate details
	fmt.Printf("Certificate:\n")
	fmt.Printf("  Data:\n")
	fmt.Printf("    Version: %d\n", object.Version)
	fmt.Printf("    Serial Number: %d\n", object.SerialNumber)
	fmt.Printf("    Signature Algorithm: %s\n", object.SignatureAlgorithm)
	fmt.Printf("    Issuer: %s\n", object.Issuer)
	fmt.Printf("    Validity:\n")
	fmt.Printf("      Not Before: %s\n", object.NotBefore.Format(time.RFC1123))
	fmt.Printf("      Not After : %s\n", object.NotAfter.Format(time.RFC1123))
	fmt.Printf("    Subject: %s\n", object.Subject)
	fmt.Printf("    Subject Public Key Algorithm: %s\n", object.PublicKeyAlgorithm)
	fmt.Printf("    Public Key:\n      %v\n", object.PublicKey)

	if len(object.Extensions) > 0 {
		fmt.Printf("  Extensions:\n")
		for _, ext := range object.Extensions {
			fmt.Printf("    - ID: %s, Critical: %t\n", ext.Id, ext.Critical)
		}
	}

	return nil
}
