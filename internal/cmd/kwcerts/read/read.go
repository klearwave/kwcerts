package read

import (
	"github.com/spf13/cobra"
)

// NewSubCommand creates the 'read' subcommand.
func NewSubCommand() *cobra.Command {
	// read the command object
	read := &cobra.Command{
		Use:   "read",
		Short: "Read certificate objects",
		Long:  `Read certificate objects`,
	}

	// add the action subcommands
	read.AddCommand(newCertificateSubCommand())

	return read
}
