package cmd

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kmeshctl",
	Short: "Root command for kmeshctl",
}

var readinessCmd = &cobra.Command{
	Use:   "readiness",
	Short: "Check if the Kmesh daemon is healthy and ready",
	Run: func(cmd *cobra.Command, args []string) {
		readinessURL := "http://localhost:8080/ready"

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(readinessURL)
		if err != nil {
			fmt.Printf("Error reaching readiness endpoint: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			fmt.Println("Kmesh daemon is ready!")
		} else {
			fmt.Printf("Kmesh daemon is not ready (status: %d)\n", resp.StatusCode)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(readinessCmd)
}
