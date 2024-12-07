package create

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/klearwave/kwcerts/pkg/types"
	"github.com/spf13/cobra"
)

// certificateExample is the example text that is displayed by the CLI to
// assist the user with usage.
const certificateExample = `
# create a new certificate certificate from a local certificate authority
kwcerts create certifcate --bits=4096 --days=3650 --common-name="My CA" \
  --ca-key=tmp/ca.key --ca-cert=tmp/ca.crt --key=tmp/server.key --cert=tmp/server.crt
`

// below are flag constants that are used multiple times
const (
	keyFileFlag  = "key"
	certFileFlag = "cert"
)

// below are default flag inputs
const (
	keyFileDefault  = "server.key"
	certFileDefault = "server.crt"
)

// newCertificateSubCommand creates the 'create ca' subcommand.
func newCertificateSubCommand() *cobra.Command {
	caInput := &types.CertificateInput{}
	certInput := &types.CertificateInput{}

	// create the command object
	ca := &cobra.Command{
		Use:     "certificate",
		Short:   "Create a new self-signed certificate from a certificate authority",
		Long:    `Create a new self-signed certificate from a certificate authority`,
		Example: certificateExample,
	}

	// add flags
	ca.Flags().IntVarP(&certInput.KeyBits, "bits", "b", int(types.Bits4096), "RSA Bits to use for the certificate authority key")
	ca.Flags().IntVarP(&certInput.ValidDays, "days", "d", 3650, "Length in days that the certificate authority is valid for")
	ca.Flags().StringVarP(&certInput.CommonName, "common-name", "n", "My Organization", "Common name for the certificate authority")
	ca.Flags().StringVar(&caInput.KeyFilePath, caKeyFileFlag, caKeyFileDefault, "Path to existing certificate authority key file")
	ca.Flags().StringVar(&caInput.CertificateFilePath, caCertFileFlag, caCertFileDefault, "Path to existing certificate authority certificate file")
	ca.Flags().StringVar(&certInput.KeyFilePath, keyFileFlag, keyFileDefault, "Output path to write the certificate key file")
	ca.Flags().StringVar(&certInput.CertificateFilePath, certFileFlag, certFileDefault, "Output path to write the certificate certificate file")
	ca.Flags().BoolVar(&certInput.Force, "force", false, "Force creation of files if existing files exist at --ca-key and --ca-cert paths")

	// set the runtime functions
	ca.PreRunE = func(_ *cobra.Command, _ []string) error { return validateCertificateCreate(caInput, certInput) }
	ca.RunE = func(_ *cobra.Command, _ []string) error { return runCertificateCreate(caInput, certInput) }

	return ca
}

// validateCertificateCreate runs the logic to validate inputs.
func validateCertificateCreate(caInput, certInput *types.CertificateInput) error {
	// validate file inputs
	for flag, file := range map[string]string{
		caKeyFileFlag:  caInput.KeyFilePath,
		caCertFileFlag: caInput.CertificateFilePath,
		keyFileFlag:    certInput.KeyFilePath,
		certFileFlag:   certInput.CertificateFilePath,
	} {
		// return an error if user input an empty value overriding the default
		if file == "" {
			return fmt.Errorf("value for flag [%s] is empty", flag)
		}
	}

	// validate key bits
	if !types.KeyBits(certInput.KeyBits).IsValid() {
		return fmt.Errorf(
			"invalid --key-bits input [%d]; valid values are [%v]",
			certInput.KeyBits,
			types.Bits2048.IsValid(),
		)
	}

	// validate days
	if certInput.ValidDays < 30 || certInput.ValidDays > 3650 {
		return fmt.Errorf("invalid --days input [%d]; valid range is [%d, %d]", certInput.ValidDays, 30, 3650)
	}

	// validate common name.  according to rfc 5280, the max length for a common name is 64
	if len(certInput.CommonName) > 64 {
		return fmt.Errorf("invalid common name length [%d]; max is 64 according to rfc 5280", len(certInput.CommonName))
	}

	return nil
}

// runCertificateCreate runs the logic to runCertificateCreate a certificate authority.
func runCertificateCreate(caInput, certInput *types.CertificateInput) error {
	// read the certificate authority caKey
	caKey := types.NewKey()
	if err := caKey.Read(caInput.KeyFilePath); err != nil {
		return fmt.Errorf("error reading certificate authority key from path [%s]; %w", certInput.KeyFilePath, err)
	}

	// create the certificate authority object
	ca := types.NewCertificateAuthority(caKey)

	// read the certificate authority certificate
	caCert := types.NewCertificate()
	if err := caCert.Read(caInput.CertificateFilePath); err != nil {
		return fmt.Errorf("error reading certificate authority cert from path [%s]; %w", certInput.CertificateFilePath, err)
	}

	// store the certificate on the ca object
	ca.Certificate = caCert

	caRequest, err := ca.Certificate.Object()
	if err != nil {
		return fmt.Errorf("error reading certificate authority object; %w", err)
	}
	ca.Certificate.Request = caRequest

	// create a key for the certificate
	key := types.NewKey()
	if err := key.Generate(types.KeyBits(certInput.KeyBits)); err != nil {
		return fmt.Errorf("error creating key for certificate authority; %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return fmt.Errorf("error generating serial number; %w", err)
	}

	certRequest := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: certInput.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(certInput.ValidDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// generate the certificate from the certificate authority
	cert := types.NewCertificate()
	cert.SetRequest(certRequest)
	if err := cert.Generate(key, ca); err != nil {
		return fmt.Errorf("error creating self-signed certificate; %w", err)
	}

	// write the files
	if err := key.Write(certInput.KeyFilePath); err != nil {
		return fmt.Errorf("error writing certificate key; %w", err)
	}

	if err := cert.Write(certInput.CertificateFilePath); err != nil {
		return fmt.Errorf("error writing certificate; %w", err)
	}

	return nil
}

// generateSerialNumber creates a large, random serial number.
func generateSerialNumber() (*big.Int, error) {
	serialNumberBytes := make([]byte, 16) // 128-bit serial number
	if _, err := rand.Read(serialNumberBytes); err != nil {
		return nil, fmt.Errorf("error generating serial number: %w", err)
	}

	// Ensure the number is positive by setting the MSB to 0
	serialNumberBytes[0] &= 0x7F

	serialNumber := new(big.Int).SetBytes(serialNumberBytes)
	return serialNumber, nil
}
