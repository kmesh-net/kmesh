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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

type Resource struct {
	Name string
	URL  string
}

var decUnstructured = yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)

func doServerSideApply(ctx context.Context, cfg *rest.Config, obj *unstructured.Unstructured) error {
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return err
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))

	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return err
	}

	mapping, err := mapper.RESTMapping(obj.GroupVersionKind().GroupKind(), obj.GroupVersionKind().Version)
	if err != nil {
		return err
	}

	var dr dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		dr = dyn.Resource(mapping.Resource).Namespace(obj.GetNamespace())
	} else {
		dr = dyn.Resource(mapping.Resource)
	}

	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	_, err = dr.Patch(ctx, obj.GetName(), types.ApplyPatchType, data, metav1.PatchOptions{
		FieldManager: "sample-controller",
	})

	return err
}

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "install kmesh with all the resources",
		Example: `# Install kmesh without version argument (defaults to main):
kmeshctl install

# Install a specific version
kmeshctl install --version <version>`,
		Run: func(cmd *cobra.Command, args []string) {
			version, err := cmd.Flags().GetString("version")
			if err != nil {
				log.Fatal(err)
			}

			kubeconfig := os.Getenv("HOME") + "/.kube/config"

			config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
			if err != nil {
				panic(err.Error())
			}

			resources := []Resource{
				{Name: "clusterRole", URL: getURL(version, "clusterrole.yaml")},
				{Name: "clusterRoleBinding", URL: getURL(version, "clusterrolebinding.yaml")},
				{Name: "kmesh", URL: getURL(version, "kmesh.yaml")},
				{Name: "l7EnvoyFilter", URL: getURL(version, "l7-envoyfilter.yaml")},
				{Name: "serviceAccount", URL: getURL(version, "serviceaccount.yaml")},
			}

			fmt.Println("install kmesh version: ", version)

			for _, resource := range resources {
				resp, err := getURLResponse(resource.URL)
				if err != nil {
					log.Fatalf("Error fetching %s: %v", resource.URL, err)
				}
				defer resp.Body.Close()

				deployYaml, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Printf("yamlFile.Get err   #%v ", err)
				}

				fmt.Println("initializing ", resource.Name)
				err = applyYaml(deployYaml, config)
				if err != nil {
					log.Fatal(err)
				}
			}
		},
	}

	cmd.Flags().String("version", "main", "Version of the resources to initialize")
	return cmd
}

func applyYaml(yamlFile []byte, config *rest.Config) error {
	multidocReader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(yamlFile)))

	for {
		buf, err := multidocReader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		obj := &unstructured.Unstructured{}
		_, _, err = decUnstructured.Decode(buf, nil, obj)
		if err != nil {
			return err
		}

		err = doServerSideApply(context.TODO(), config, obj)
		if err != nil {
			return err
		}
	}

	return nil
}

func getURL(version, filename string) string {
	if version != "main" {
		return "https://raw.githubusercontent.com/kmesh-net/kmesh/refs/heads/release-" + version + "/deploy/yaml/" + filename
	}
	return "https://raw.githubusercontent.com/kmesh-net/kmesh/refs/heads/" + version + "/deploy/yaml/" + filename
}

func getURLResponse(url string) (*http.Response, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
