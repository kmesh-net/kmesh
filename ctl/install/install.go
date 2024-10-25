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

package install

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
)

type GitHubFile struct {
	Name        string `json:"name"`
	DownloadURL string `json:"download_url"`
}

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "install kmesh with all the resources",
		Example: `# Install all kmesh resources (defaults to main):
kmeshctl install

# Install a specific version of kmesh
kmeshctl install --version 0.5`,
		Run: func(cmd *cobra.Command, args []string) {
			version, err := cmd.Flags().GetString("version")
			if err != nil {
				log.Fatal(err)
			}

			cli, err := utils.CreateKubeClient()
			if err != nil {
				log.Fatalf("failed to create cli client: %v", err)
				os.Exit(1)
			}

			fmt.Println("install kmesh version: ", version)

			combinedYAMLFile := getYAMLFile()
			err = cli.ApplyYAMLContents("", combinedYAMLFile)
			if err != nil {
				log.Fatal(err)
			}
		},
	}

	cmd.Flags().String("version", "main", "Version of the resources to initialize")
	return cmd
}

func getYAMLFile() string {
	url := fmt.Sprintf("https://api.github.com/repos/kmesh-net/kmesh/contents/deploy/yaml?ref=main")

	resp, err := http.Get(url)
	if err != nil {
		log.Fatal("error fetching files:", err)
	}
	defer resp.Body.Close()

	var files []GitHubFile
	err = json.NewDecoder(resp.Body).Decode(&files)
	if err != nil {
		log.Fatal("error decoding JSON:", err)
	}

	var combinedYAML string

	for _, file := range files {
		if filepath.Ext(file.Name) == ".yaml" {
			resp, err := http.Get(file.DownloadURL)
			if err != nil {
				log.Fatal(err)
			}
			defer resp.Body.Close()

			deployYaml, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Fatalf("yamlFile.Get err   #%v ", err)
			}

			combinedYAML += string(deployYaml) + "\n---\n"
		}
	}

	return combinedYAML
}
