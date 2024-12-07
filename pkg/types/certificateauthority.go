package types

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/klearwave/kwcerts/pkg/utils"
)

// certificateAuthority represents a generated certificate authority object.
type certificateAuthority struct {
	Certificate *certificate
	Key         *key
}

// CertificateAuthorityInput represents the input needed to generate a certificate
// authority object.
type CertificateAuthorityInput struct {
	Force bool

	KeyBits    int
	CommonName string
	ValidDays  int

	CertificateFilePath string
	KeyFilePath         string
}

// NewCertificateAuthority generates a new certificate authority object given a key.
func NewCertificateAuthority(caKey *key, input *CertificateAuthorityInput) *certificateAuthority {
	cert := NewCertificate()

	cert.SetRequest(&x509.Certificate{
		SerialNumber: big.NewInt(1), // Use a unique serial number for each certificate
		Subject: pkix.Name{
			CommonName: input.CommonName,
			// TODO: we may want this later but just focus on org for name
			// Country:      []string{"US"},
			// Province:     []string{"California"},
			// Locality:     []string{"San Francisco"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(input.ValidDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // Self-signed CA
	})

	return &certificateAuthority{
		Key:         caKey,
		Certificate: cert,
	}
}

// GenerateRoot generates the root certificate for the certificate authority and stores the data
// in a certificate.
func (ca *certificateAuthority) GenerateRoot(input *CertificateAuthorityInput) error {
	// create a new certificate authority certificate from the key
	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Use a unique serial number for each certificate
		Subject: pkix.Name{
			CommonName: input.CommonName,
			// TODO: we may want this later but just focus on org for name
			// Country:      []string{"US"},
			// Province:     []string{"California"},
			// Locality:     []string{"San Francisco"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(input.ValidDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // Self-signed CA
	}

	// self-sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &ca.Key.PublicKey, ca.Key.PrivateKey)
	if err != nil {
		return fmt.Errorf("error creating certificate authority certificate; %w", err)
	}

	// encode the certificate to PEM format
	ca.Certificate.CertificateData = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// self-sign the certificate
	ca.Certificate.Generate(caCert, ca.Key, ca)

	return nil
}

// WriteKey writes certificate authority key data to a file.
func (ca *certificateAuthority) WriteKey(keyPath string) error {
	if ca.Key == nil {
		return fmt.Errorf("missing key from certificate authority object")
	}

	// extract the private key content
	content, err := ca.Key.PrivateKeyBytes()
	if err != nil {
		return fmt.Errorf("error extracting private key content; %w", err)
	}

	return utils.WriteFile(keyPath, content)
}

// WriteCert writes certificate authority cert data to a file.
func (ca *certificateAuthority) WriteCert(certPath string) error {
	if ca.Certificate == nil {
		return fmt.Errorf("missing certificate object from certificate authority object")
	}

	if len(ca.Certificate.CertificateData) == 0 {
		return fmt.Errorf("missing certificate data from certificate authority object")
	}

	return utils.WriteFile(certPath, ca.Certificate.CertificateData)
}
