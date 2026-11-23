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

package kmesh

import (
	"testing"

	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
)

// TestMeshBoundary verifies communication between applications inside and outside the Kmesh Mesh.
// This is critical for supporting incremental migration and interoperability with unmeshed services.
func TestMeshBoundary(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		if len(apps.Unmeshed) == 0 || len(apps.EnrolledToKmesh) == 0 || len(apps.ServiceWithWaypointAtServiceGranularity) == 0 {
			t.Skip("one or more required applications are not deployed for boundary testing")
		}

		unmeshed := apps.Unmeshed[0]
		enrolled := apps.EnrolledToKmesh[0]
		waypoint := apps.ServiceWithWaypointAtServiceGranularity[0]

		testCases := []struct {
			name  string
			src   echo.Instance
			dst   echo.Instance
			check echo.Checker
		}{
			{
				name:  "meshed to unmeshed",
				src:   enrolled,
				dst:   unmeshed,
				check: check.And(check.OK(), IsL4()),
			},
			{
				name:  "unmeshed to meshed",
				src:   unmeshed,
				dst:   enrolled,
				check: check.And(check.OK(), IsL4()),
			},
			{
				name:  "waypoint to unmeshed",
				src:   waypoint,
				dst:   unmeshed,
				check: check.And(check.OK(), IsL4()),
			},
			{
				name:  "unmeshed to waypoint",
				src:   unmeshed,
				dst:   waypoint,
				check: check.And(check.OK(), IsL4()),
			},
		}

		for _, tc := range testCases {
			t.NewSubTest(tc.name).Run(func(t framework.TestContext) {
				tc.src.CallOrFail(t, echo.CallOptions{
					To:     tc.dst,
					Port:   echo.Port{Name: "http"},
					Scheme: scheme.HTTP,
					Count:  5,
					Check:  tc.check,
				})
			})
		}
	})
}
