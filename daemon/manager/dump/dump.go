package dump

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"kmesh.net/kmesh/pkg/status"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Dump xds workloads",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			_ = RunDump(cmd, args)
		},
	}
	return cmd
}

func RunDump(cmd *cobra.Command, args []string) error {
	mode := args[0]
	if mode != "ads" && mode != "workload" {
		fmt.Println("Error: Argument must be 'ads' or 'workload'")
		cmd.Usage()
		os.Exit(1)
	} else {
		url := status.GetConfigDumpAddr(mode)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error reading response: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(string(body))
	}
	return nil
}
