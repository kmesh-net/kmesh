package version

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/pkg/version"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version of kmesh daemon",
		Run: func(cmd *cobra.Command, args []string) {
			_ = RunVersion(cmd)
		},
	}
	return cmd
}

// RunVersion provides the version information of kmesh daemon in format depending on arguments
// specified in cobra.Command.
func RunVersion(cmd *cobra.Command) error {
	v := version.Get()

	y, err := json.MarshalIndent(&v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(y))

	return nil
}
