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

package namespace

import (
	"context"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"istio.io/api/label"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kmesh.net/kmesh/ctl/utils"
)

var (
	DataplaneModeKmesh    = "Kmesh"
	KmeshUseWaypointLabel = "istio.io/use-waypoint"
)

func NewCmd() *cobra.Command {
	namespaceCmd := &cobra.Command{
		Use:   "namespace",
		Short: "Manage Kmesh namespaces",
		Long:  "A group of commands used to manage Kmesh namespaces",
		Example: `  # List all namespaces enrolled in Kmesh
  kmeshctl namespace list`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("unknown subcommand %q", args[0])
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.HelpFunc()(cmd, args)
			return nil
		},
	}

	namespaceListCmd := &cobra.Command{
		Use:   "list",
		Short: "List Kmesh enrolled namespaces",
		Long:  "List all namespaces that have the istio.io/dataplane-mode=Kmesh label",
		Example: `  # List all Kmesh namespaces
  kmeshctl namespace list`,
		RunE: func(cmd *cobra.Command, args []string) error {
			kubeClient, err := utils.CreateKubeClient()
			if err != nil {
				return fmt.Errorf("failed to create Kubernetes client: %v", err)
			}

			// We need to list namespaces
			labelSelector := fmt.Sprintf("%s=%s", label.IoIstioDataplaneMode.Name, DataplaneModeKmesh)
			nsList, err := kubeClient.Kube().CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{
				LabelSelector: labelSelector,
			})
			if err != nil {
				return fmt.Errorf("failed to list namespaces: %v", err)
			}

			writer := cmd.OutOrStdout()
			if len(nsList.Items) == 0 {
				fmt.Fprintln(writer, "No Kmesh namespaces found.")
				return nil
			}

			w := new(tabwriter.Writer).Init(writer, 0, 8, 5, ' ', 0)
			fmt.Fprintln(w, "NAME\tWAYPOINT")

			for _, ns := range nsList.Items {
				waypoint := ns.Labels[KmeshUseWaypointLabel]
				if waypoint == "" {
					waypoint = "None"
				}
				fmt.Fprintf(w, "%s\t%s\n", ns.Name, waypoint)
			}
			return w.Flush()
		},
	}

	namespaceCmd.AddCommand(namespaceListCmd)

	return namespaceCmd
}
