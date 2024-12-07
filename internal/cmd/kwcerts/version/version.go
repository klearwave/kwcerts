package version

import (
	"fmt"

	"github.com/spf13/cobra"
)

var version = "unstable"

const versionExample = `
kwcerts version
`

func NewCommand() *cobra.Command {
	// create the command
	command := &cobra.Command{
		Use:     "version",
		Short:   "Print version information",
		Long:    `Print version information`,
		Run:     func(_ *cobra.Command, _ []string) { run() },
		Example: versionExample,
	}

	return command
}

//nolint:forbidigo
func run() {
	fmt.Printf("%s\n", version)
}
