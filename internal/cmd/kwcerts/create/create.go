package create

import (
	"github.com/spf13/cobra"
)

// NewSubCommand creates the 'create' subcommand.
func NewSubCommand() *cobra.Command {
	// create the command object
	create := &cobra.Command{
		Use:   "create",
		Short: "Create certificate objects",
		Long:  `Create certificate objects`,
	}

	// add the action subcommands
	create.AddCommand(newCertificateAuthoritySubCommand())

	return create
}
