package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/klearwave/kwcerts/internal/cmd/kwcerts/create"
	"github.com/klearwave/kwcerts/internal/cmd/kwcerts/read"
	"github.com/klearwave/kwcerts/internal/cmd/kwcerts/version"
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(command *cobra.Command) {
	err := command.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// main executes the main program loop.
func main() {
	kwcerts := &cobra.Command{
		Use:   "kwcerts",
		Short: "Manage self-signed certificates",
		Long:  `Manage self-signed certificates`,
	}

	// add version subcommand for printing version information
	kwcerts.AddCommand(version.NewCommand())

	// add certificate object subcommands
	kwcerts.AddCommand(create.NewSubCommand())
	kwcerts.AddCommand(read.NewSubCommand())

	Execute(kwcerts)
}
