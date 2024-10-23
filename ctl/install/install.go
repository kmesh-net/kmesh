package install

import (
	"bufio"
	"bytes"
	"io"
	"net/http"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"

	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
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

			fmt.Println("using version: ", version)

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
