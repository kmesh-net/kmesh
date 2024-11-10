package common

import (
	"github.com/spf13/cobra"
	"kmesh.net/kmesh/ctl/accesslog"
	"kmesh.net/kmesh/ctl/dump"
	logcmd "kmesh.net/kmesh/ctl/log"
	"kmesh.net/kmesh/ctl/version"
	"kmesh.net/kmesh/ctl/waypoint"
)

func GetRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "kmeshctl",
		Short:        "Kmesh command line tools to operate and debug Kmesh",
		SilenceUsage: true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	rootCmd.AddCommand(logcmd.NewCmd())
	rootCmd.AddCommand(dump.NewCmd())
	rootCmd.AddCommand(waypoint.NewCmd())
	rootCmd.AddCommand(version.NewCmd())
	rootCmd.AddCommand(accesslog.NewCmd())

	return rootCmd
}
