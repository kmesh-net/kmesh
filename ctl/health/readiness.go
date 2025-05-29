/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
