package types

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/klearwave/kwcerts/pkg/utils"
)

// certificate represents a generated certificate object.
type certificate struct {
	CertificateData []byte
	Request         *x509.Certificate
}

// CertificateInput represents the input needed to work with certificate objects.
type CertificateInput struct {
	Force                      bool
	KubernetesServiceName      string
	KubernetesServiceNamespace string

	KeyBits   int
	ValidDays int

	CommonName              string
	Organization            string
	Country                 string
	State                   string
	City                    string
	SubjectAlternativeNames []string

	CertificateFilePath string
	KeyFilePath         string
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
	if c.Request == nil {
		return errors.New("missing request from certificate")
	}

	if ca.Certificate.Request == nil {
		return errors.New("missing request from ca certificate")
	}

	// create the new certificate signed by the CA
	certBytes, err := x509.CreateCertificate(rand.Reader, c.Request, ca.Certificate.Request, &k.PublicKey, ca.Key.PrivateKey)
	if err != nil {
		return fmt.Errorf("error creating certificate; %w", err)
	}

	// encode the new certificate to PEM format
	c.CertificateData = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return nil
}

// Write writes certificate data to a file.
func (c *certificate) Write(certPath string) error {
	if len(c.CertificateData) == 0 {
		return fmt.Errorf("missing certificate data from certificate authority object")
	}

	return utils.WriteFile(certPath, c.CertificateData)
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

	// marshal the public key into DER format
	publicKey, err := x509.MarshalPKIXPublicKey(object.PublicKey)
	if err != nil {
		return fmt.Errorf("error marshal public key; %w", err)
	}

	// encode the DER bytes into a PEM block
	var pemBuffer bytes.Buffer
	err = pem.Encode(&pemBuffer, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKey,
	})
	if err != nil {
		return fmt.Errorf("error encoding public key to PEM; %w", err)
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
	fmt.Printf("    Subject Alternative Names: %v\n", object.DNSNames)
	fmt.Printf("    Public Key:\n%v\n", pemBuffer.String())

	if len(object.Extensions) > 0 {
		fmt.Printf("  Extensions:\n")
		for _, ext := range object.Extensions {
			fmt.Printf("    - ID: %s, Critical: %t\n", ext.Id, ext.Critical)
		}
	}

	return nil
}

// SetCertificateFields sets x509 certificate object fields from a CertificateInput object.
func (input *CertificateInput) SetCertificateFields(cert *x509.Certificate) {
	if input.Organization != "" {
		cert.Subject.Organization = []string{input.Organization}
	}

	if input.Country != "" {
		cert.Subject.Country = []string{input.Country}
	}

	if input.State != "" {
		cert.Subject.Province = []string{input.State}
	}

	if input.City != "" {
		cert.Subject.Locality = []string{input.City}
	}

	if len(input.SubjectAlternativeNames) > 0 {
		cert.DNSNames = input.SubjectAlternativeNames
	}
}
