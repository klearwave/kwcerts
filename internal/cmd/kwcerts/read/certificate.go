package read

import (
	"fmt"
	"os"

	"github.com/klearwave/kwcerts/pkg/types"
	"github.com/spf13/cobra"
)

// certificateExample is the example text that is displayed by the CLI to
// assist the user with usage.
const certificateExample = `
# read a certificate
kwcerts read cert --cert-file tmp/ca.crt
`

// newCertificateSubCommand creates the 'read certificate' subcommand.
func newCertificateSubCommand() *cobra.Command {
	var certFile string

	// create the command object
	cert := &cobra.Command{
		Use:     "certificate",
		Aliases: []string{"cert"},
		Short:   "Read a certificate",
		Long:    `Read a certificate`,
		Example: certificateExample,
	}

	// add flags
	cert.Flags().StringVarP(&certFile, "cert-file", "f", "ca.crt", "Path of file containing certificate to read")

	// set the runtime functions
	cert.PreRunE = func(_ *cobra.Command, _ []string) error { return validateRead(certFile) }
	cert.RunE = func(_ *cobra.Command, _ []string) error { return runRead(certFile) }

	return cert
}

// validateRead runs the logic to validate inputs.
func validateRead(path string) error {
	// return an error if user input an empty value overriding the default
	if path == "" {
		return fmt.Errorf("cert-file not provided")
	}

	// if file exists return nil, otherwise return an error
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}

	return fmt.Errorf("cert-file [%s] does not exist", path)

}

// runRead runs the logic to runRead a certificate authority.
func runRead(path string) error {
	cert := types.NewCertificate()
	if err := cert.Read(path); err != nil {
		return fmt.Errorf("error creating certificate object from path [%s]; %w", path, err)
	}

	if err := cert.Print(); err != nil {
		return fmt.Errorf("error printing certificate contents from path [%s]; %w", path, err)
	}

	return nil
}
