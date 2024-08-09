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

package controller

import (
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/workload"
	"kmesh.net/kmesh/pkg/utils"
)

func TestController_Start(t *testing.T) {
	patch := gomonkey.NewPatches()
	patch.ApplyFunc(utils.GetK8sclient, func() (kubernetes.Interface, error) {
		client := fake.NewSimpleClientset()
		return client, nil
	})
	defer patch.Reset()

	t.Run("Enable Bypass", func(t *testing.T) {
		stopCh := make(chan struct{})
		defer close(stopCh)
		c := &Controller{
			enableByPass: true,
		}

		err := c.Start(stopCh)
		assert.NoError(t, err)
	})

	t.Run("Workload Mode", func(t *testing.T) {
		patch := gomonkey.NewPatches()
		patch.ApplyFunc(workload.NewController, func(bpfWorkload *bpf.BpfKmeshWorkload) *workload.Controller {
			return nil
		})
		defer patch.Reset()
		stopCh := make(chan struct{})
		defer close(stopCh)
		c := &Controller{
			mode: constants.WorkloadMode,
		}

		err := c.Start(stopCh)
		assert.Error(t, err)
	})

	t.Run("Ads Mode", func(t *testing.T) {
		stopCh := make(chan struct{})
		defer close(stopCh)
		c := &Controller{
			mode: constants.AdsMode,
		}

		err := c.Start(stopCh)
		assert.Error(t, err)
		// Add assertions for the expected behavior in ads mode
	})

	t.Run("Workload Mode with Secret Manager", func(t *testing.T) {
		stopCh := make(chan struct{})
		defer close(stopCh)
		c := &Controller{
			mode:                constants.WorkloadMode,
			enableSecretManager: true,
		}

		err := c.Start(stopCh)
		assert.Error(t, err)
	})

	// Add more test cases as needed
}
