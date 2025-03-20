//go:build integ
// +build integ

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

// NOTE: THE CODE IN THIS FILE IS MAINLY REFERENCED FROM ISTIO INTEGRATION
// FRAMEWORK(https://github.com/istio/istio/tree/master/tests/integration)
// AND ADAPTED FOR KMESH.

package kmesh

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/go-multierror"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
	kubetest "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/util/retry"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestKmeshRestart(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		src := apps.EnrolledToKmesh[0]
		dst := apps.ServiceWithWaypointAtServiceGranularity
		options := echo.CallOptions{
			To:    dst,
			Count: 1,
			// Determine whether it is managed by Kmesh by passing through Waypoint.
			Check: httpValidator,
			Port: echo.Port{
				Name: "http",
			},
			Retry: echo.Retry{NoRetry: true},
		}

		g := NewGenerator(t, Config{
			Source:   src,
			Options:  options,
			Interval: 50 * time.Millisecond,
		}).Start()

		for i := 0; i < 3; i++ {
			restartKmesh(t)
		}

		g.Stop().CheckSuccessRate(t, 1)
	})
}

func restartKmesh(t framework.TestContext) {
	patchOpts := metav1.PatchOptions{}
	patchData := fmt.Sprintf(`{
			"spec": {
				"template": {
					"metadata": {
						"annotations": {
							"kubectl.kubernetes.io/restartedAt": %q
						}
					}
				}
			}
		}`, time.Now().Format(time.RFC3339))
	ds := t.Clusters().Default().Kube().AppsV1().DaemonSets(KmeshNamespace)
	_, err := ds.Patch(context.Background(), KmeshDaemonsetName, types.StrategicMergePatchType, []byte(patchData), patchOpts)
	if err != nil {
		t.Fatal(err)
	}

	if err := retry.UntilSuccess(func() error {
		d, err := ds.Get(context.Background(), KmeshDaemonsetName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if !daemonsetsetComplete(d) {
			return fmt.Errorf("rollout is not yet done")
		}
		return nil
	}, retry.Timeout(60*time.Second), retry.Delay(2*time.Second)); err != nil {
		t.Fatal("failed to wait for Kmesh rollout status for: %v", err)
	}
	if _, err := kubetest.CheckPodsAreReady(kubetest.NewPodFetch(t.AllClusters()[0], KmeshNamespace, "app=kmesh")); err != nil {
		t.Fatal(err)
	}
}

func daemonsetsetComplete(ds *appsv1.DaemonSet) bool {
	return ds.Status.UpdatedNumberScheduled == ds.Status.DesiredNumberScheduled && ds.Status.NumberReady == ds.Status.DesiredNumberScheduled && ds.Status.ObservedGeneration >= ds.Generation
}

const (
	defaultInterval = 1 * time.Second
	defaultTimeout  = 15 * time.Second
)

// Config for a traffic Generator.
type Config struct {
	// Source of the traffic.
	Source echo.Caller

	// Options for generating traffic from the Source to the target.
	Options echo.CallOptions

	// Interval between successive call operations. If not set, defaults to 1 second.
	Interval time.Duration

	// Maximum time to wait for traffic to complete after stopping. If not set, defaults to 15 seconds.
	StopTimeout time.Duration
}

// Generator of traffic between echo instances. Every time interval
// (as defined by Config.Interval), a grpc request is sent to the source pod,
// causing it to send a request to the destination echo server. Results are
// captured for each request for later processing.
type Generator interface {
	// Start sending traffic.
	Start() Generator

	// Stop sending traffic and wait for any in-flight requests to complete.
	// Returns the Result
	Stop() Result
}

// NewGenerator returns a new Generator with the given configuration.
func NewGenerator(t test.Failer, cfg Config) Generator {
	fillInDefaults(&cfg)
	return &generator{
		Config:  cfg,
		t:       t,
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

var _ Generator = &generator{}

type generator struct {
	Config
	t       test.Failer
	result  Result
	stop    chan struct{}
	stopped chan struct{}
}

func (g *generator) Start() Generator {
	go func() {
		t := time.NewTimer(g.Interval)
		for {
			select {
			case <-g.stop:
				t.Stop()
				close(g.stopped)
				return
			case <-t.C:
				result, err := g.Source.Call(g.Options)
				g.result.add(result, err)
				if err != nil {
					g.t.Logf("-- encounter error")
					return
				}
				t.Reset(g.Interval)
			}
		}
	}()
	return g
}

func (g *generator) Stop() Result {
	// Trigger the generator to stop.
	close(g.stop)

	// Wait for the generator to exit.
	t := time.NewTimer(g.StopTimeout)
	select {
	case <-g.stopped:
		t.Stop()
		if g.result.TotalRequests == 0 {
			g.t.Fatal("no requests completed before stopping the traffic generator")
		}
		return g.result
	case <-t.C:
		g.t.Fatal("timed out waiting for result")
	}
	// Can never happen, but the compiler doesn't know that Fatal terminates
	return Result{}
}

func fillInDefaults(cfg *Config) {
	if cfg.Interval == 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.StopTimeout == 0 {
		cfg.StopTimeout = defaultTimeout
	}
	if cfg.Options.Check == nil {
		cfg.Options.Check = check.OK()
	}
}

// Result of a traffic generation operation.
type Result struct {
	TotalRequests      int
	SuccessfulRequests int
	Error              error
}

func (r Result) String() string {
	buf := &bytes.Buffer{}

	_, _ = fmt.Fprintf(buf, "TotalRequests:       %d\n", r.TotalRequests)
	_, _ = fmt.Fprintf(buf, "SuccessfulRequests:  %d\n", r.SuccessfulRequests)
	_, _ = fmt.Fprintf(buf, "PercentSuccess:      %f\n", r.PercentSuccess())
	_, _ = fmt.Fprintf(buf, "Errors:              %v\n", r.Error)

	return buf.String()
}

func (r *Result) add(result echo.CallResult, err error) {
	count := result.Responses.Len()
	if count == 0 {
		count = 1
	}

	r.TotalRequests += count
	if err != nil {
		r.Error = multierror.Append(r.Error, fmt.Errorf("request %d: %v", r.TotalRequests, err))
	} else {
		r.SuccessfulRequests += count
	}
}

func (r Result) PercentSuccess() float64 {
	return float64(r.SuccessfulRequests) / float64(r.TotalRequests)
}

// CheckSuccessRate asserts that a minimum success threshold was met.
func (r Result) CheckSuccessRate(t test.Failer, minimumPercent float64) {
	t.Helper()
	if r.PercentSuccess() < minimumPercent {
		t.Fatalf("Minimum success threshold, %f, was not met. %d/%d (%f) requests failed: %v",
			minimumPercent, r.SuccessfulRequests, r.TotalRequests, r.PercentSuccess(), r.Error)
	}
	if r.SuccessfulRequests == r.TotalRequests {
		t.Logf("traffic checker succeeded with all successful requests (%d/%d)", r.SuccessfulRequests, r.TotalRequests)
	} else {
		t.Logf("traffic checker met minimum threshold, with %d/%d successes, but encountered some failures: %v", r.SuccessfulRequests, r.TotalRequests, r.Error)
	}
}
