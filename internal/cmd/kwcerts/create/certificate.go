package create

import (
	"fmt"
	"os"

	"github.com/klearwave/kwcerts/pkg/types"
	"github.com/spf13/cobra"
)

// certificateExample is the example text that is displayed by the CLI to
// assist the user with usage.
const certificateExample = `
# create a new certificate certificate from a local certificate authority
kwcerts create certifcate --bits=4096 --days=3650 --common-name="My CA" \
  --ca-key=tmp/ca.key --ca-cert=tmp/ca.crt
`

// newCertificateSubCommand creates the 'create ca' subcommand.
func newCertificateSubCommand() *cobra.Command {
	input := &types.CertificateAuthorityInput{}

	// create the command object
	ca := &cobra.Command{
		Use:     "certificate",
		Short:   "Create a new self-signed certificate from a certificate authority",
		Long:    `Create a new self-signed certificate from a certificate authority`,
		Example: certificateExample,
	}

	// add flags
	ca.Flags().IntVarP(&input.KeyBits, "bits", "b", int(types.Bits4096), "RSA Bits to use for the certificate authority key")
	ca.Flags().IntVarP(&input.ValidDays, "days", "d", 3650, "Length in days that the certificate authority is valid for")
	ca.Flags().StringVarP(&input.CommonName, "common-name", "n", "My Organization", "Common name for the certificate authority")
	ca.Flags().StringVar(&input.KeyFilePath, caKeyFileFlag, caKeyFileDefault, "Output path to write the certificate authority key file")
	ca.Flags().StringVar(&input.CertificateFilePath, caCertFileFlag, caCertFileDefault, "Output path to write the certificate authority certificate file")
	ca.Flags().BoolVar(&input.Force, "force", false, "Force creation of files if existing files exist at --ca-key and --ca-cert paths")

	// set the runtime functions
	ca.PreRunE = func(_ *cobra.Command, _ []string) error { return validateCertificateCreate(input) }
	ca.RunE = func(_ *cobra.Command, _ []string) error { return runCertificateCreate(input) }

	return ca
}

// validateCertificateCreate runs the logic to validate inputs.
func validateCertificateCreate(input *types.CertificateAuthorityInput) error {
	// validate file inputs
	for flag, file := range map[string]string{
		caKeyFileFlag:  input.KeyFilePath,
		caCertFileFlag: input.CertificateFilePath,
	} {
		// return an error if user input an empty value overriding the default
		if file == "" {
			return fmt.Errorf("value for flag [%s] is empty", flag)
		}

		// if force is not requested, ensure a file does not exist
		if !input.Force {
			_, err := os.Stat(file)
			if err == nil {
				return fmt.Errorf(
					"file [%s] exists for flag [%s] and force was not requested",
					file,
					flag,
				)
			}
		}
	}

	// validate key bits
	if !types.KeyBits(input.KeyBits).IsValid() {
		return fmt.Errorf(
			"invalid --key-bits input [%d]; valid values are [%v]",
			input.KeyBits,
			types.Bits2048.IsValid(),
		)
	}

	// validate days
	if input.ValidDays < 30 || input.ValidDays > 3650 {
		return fmt.Errorf("invalid --days input [%d]; valid range is [%d, %d]", input.ValidDays, 30, 3650)
	}

	// validate common name.  according to rfc 5280, the max length for a common name is 64
	if len(input.CommonName) > 64 {
		return fmt.Errorf("invalid common name length [%d]; max is 64 according to rfc 5280", len(input.CommonName))
	}

	return nil
}

// runCertificateCreate runs the logic to runCertificateCreate a certificate authority.
func runCertificateCreate(input *types.CertificateAuthorityInput) error {
	// read the certificate authority caKey
	caKey := types.NewKey()
	if err := caKey.Read(input.KeyFilePath); err != nil {
		return fmt.Errorf("error reading certificate authority key from path [%s]; %w", input.KeyFilePath, err)
	}

	// read the certificate authority certificate
	caCert := types.NewCertificate()
	if err := caCert.Read(input.CertificateFilePath); err != nil {
		return fmt.Errorf("error reading certificate authority cert from path [%s]; %w", input.CertificateFilePath, err)
	}

	// create a key for the certificate
	key := types.NewKey()
	if err := key.Generate(types.KeyBits(input.KeyBits)); err != nil {
		return fmt.Errorf("error creating key for certificate authority; %w", err)
	}

	// // create a key for the certificate
	// key, err := types.NewKey(types.KeyBits(input.KeyBits))
	// if err != nil {
	// 	return fmt.Errorf("error creating key for certificate; %w", err)
	// }

	// // write the files
	// if err := ca.WriteKey(input.KeyFilePath); err != nil {
	// 	return fmt.Errorf("error writing certificate authority key; %w", err)
	// }

	// if err := ca.WriteCert(input.CertificateFilePath); err != nil {
	// 	return fmt.Errorf("error writing certificate authority certificate; %w", err)
	// }

	return nil
}
