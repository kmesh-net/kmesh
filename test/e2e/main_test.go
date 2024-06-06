//go:build integ
// +build integ

package kmesh

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/resource"
	"istio.io/istio/pkg/test/scopes"
	"istio.io/istio/tests/integration/security/util/cert"
)

var (
	i istio.Instance

	// KmeshSrc is the location of Kmesh source.
	KmeshSrc = getDefaultKmeshSrc()

	KmeshNS = "kmesh-system"
)

func getDefaultKmeshSrc() string {
	_, b, _, _ := runtime.Caller(0)

	// Root folder of the project.
	// This relies on the fact that this file is 2 levels up from the root; if this changes, adjust the path below.
	return filepath.Join(filepath.Dir(b), "../..")
}

func TestMain(m *testing.M) {
	// nolint: staticcheck
	framework.
		NewSuite(m).
		Setup(func(t resource.Context) error {
			t.Settings().Ambient = true
			return nil
		}).
		Setup(istio.Setup(&i, func(ctx resource.Context, cfg *istio.Config) {
			// can't deploy VMs without eastwest gateway
			ctx.Settings().SkipVMs()
			cfg.EnableCNI = true
			cfg.DeployEastWestGW = false
		}, cert.CreateCASecretAlt)).
		Setup(func(t resource.Context) error {
			scopes.Framework.Info("=== BEGIN: Deploy Kmesh ===")

			err := SetupKmesh(t)
			if err != nil {
				scopes.Framework.Info("=== FAILED: Deploy Kmesh ===")
				return err
			}

			scopes.Framework.Info("=== SUCCEEDED: Deploy Kmesh ===")

			return nil
		}).
		Run()
}

func SetupKmesh(ctx resource.Context) error {
	yamls, err := getKmeshYamls()
	if err != nil {
		return err
	}

	return ctx.Clusters().Default().ApplyYAMLFiles("", yamls...)
}

func getKmeshYamls() ([]string, error) {
	KmeshInstallFilePath := path.Join(KmeshSrc, "deploy/yaml/")

	files, err := os.ReadDir(KmeshInstallFilePath)
	if err != nil {
		return nil, err
	}

	results := []string{}
	for _, file := range files {
		if file.IsDir() {
			// TODO: consider the situation of multiple directories in the future.
			continue
		}

		results = append(results, filepath.Join(KmeshInstallFilePath, file.Name()))
	}

	return results, nil
}
