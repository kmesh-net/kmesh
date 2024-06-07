//go:build integ
// +build integ

package kmesh

import (
	"testing"
	"time"

	"istio.io/istio/pkg/test/framework"
)

func TestKmesh(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		time.Sleep(100 * time.Second)
	})
}
