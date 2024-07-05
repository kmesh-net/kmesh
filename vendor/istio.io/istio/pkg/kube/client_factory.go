//  Copyright Istio Authors
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package kube

import (
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/discovery"
	diskcached "k8s.io/client-go/discovery/cached/disk"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"istio.io/istio/pkg/lazy"
)

var _ PartialFactory = &clientFactory{}

// clientFactory partially implements the kubectl util.Factory, which is provides access to various k8s clients.
// The full Factory can be built with MakeKubeFactory.
// This split is to avoid huge dependencies.
type clientFactory struct {
	clientConfig clientcmd.ClientConfig

	expander lazy.Lazy[meta.RESTMapper]
	mapper   lazy.Lazy[meta.ResettableRESTMapper]

	discoveryClient lazy.Lazy[discovery.CachedDiscoveryInterface]
}

// newClientFactory creates a new util.Factory from the given clientcmd.ClientConfig.
func newClientFactory(clientConfig clientcmd.ClientConfig, diskCache bool) *clientFactory {
	out := &clientFactory{
		clientConfig: clientConfig,
	}

	out.discoveryClient = lazy.NewWithRetry(func() (discovery.CachedDiscoveryInterface, error) {
		restConfig, err := out.ToRESTConfig()
		if err != nil {
			return nil, err
		}
		// Setup cached discovery. CLIs uses disk cache, controllers use memory cache.
		if diskCache {
			// From https://github.com/kubernetes/cli-runtime/blob/4fdf49ae46a0caa7fafdfe97825c6129d5153f06/pkg/genericclioptions/config_flags.go#L288

			cacheDir := filepath.Join(homedir.HomeDir(), ".kube", "cache")

			httpCacheDir := filepath.Join(cacheDir, "http")
			discoveryCacheDir := computeDiscoverCacheDir(filepath.Join(cacheDir, "discovery"), restConfig.Host)

			return diskcached.NewCachedDiscoveryClientForConfig(restConfig, discoveryCacheDir, httpCacheDir, 6*time.Hour)
		}
		d, err := discovery.NewDiscoveryClientForConfig(restConfig)
		if err != nil {
			return nil, err
		}
		return memory.NewMemCacheClient(d), nil
	})
	out.mapper = lazy.NewWithRetry(func() (meta.ResettableRESTMapper, error) {
		discoveryClient, err := out.ToDiscoveryClient()
		if err != nil {
			return nil, err
		}
		return restmapper.NewDeferredDiscoveryRESTMapper(discoveryClient), nil
	})
	out.expander = lazy.NewWithRetry(func() (meta.RESTMapper, error) {
		discoveryClient, err := out.discoveryClient.Get()
		if err != nil {
			return nil, err
		}
		mapper, err := out.mapper.Get()
		if err != nil {
			return nil, err
		}
		return restmapper.NewShortcutExpander(mapper, discoveryClient, func(string) {}), nil
	})
	return out
}

func (c *clientFactory) ToRESTConfig() (*rest.Config, error) {
	restConfig, err := c.clientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	return SetRestDefaults(restConfig), nil
}

func (c *clientFactory) ToDiscoveryClient() (discovery.CachedDiscoveryInterface, error) {
	return c.discoveryClient.Get()
}

// overlyCautiousIllegalFileCharacters matches characters that *might* not be supported.  Windows is really restrictive, so this is really restrictive
var overlyCautiousIllegalFileCharacters = regexp.MustCompile(`[^(\w/.)]`)

// computeDiscoverCacheDir takes the parentDir and the host and comes up with a "usually non-colliding" name.
func computeDiscoverCacheDir(parentDir, host string) string {
	// strip the optional scheme from host if its there:
	schemelessHost := strings.Replace(strings.Replace(host, "https://", "", 1), "http://", "", 1)
	// now do a simple collapse of non-AZ09 characters.  Collisions are possible but unlikely.  Even if we do collide the problem is short lived
	safeHost := overlyCautiousIllegalFileCharacters.ReplaceAllString(schemelessHost, "_")
	return filepath.Join(parentDir, safeHost)
}

func (c *clientFactory) ToRESTMapper() (meta.RESTMapper, error) {
	return c.expander.Get()
}

func (c *clientFactory) ToRawKubeConfigLoader() clientcmd.ClientConfig {
	return c.clientConfig
}

func (c *clientFactory) DynamicClient() (dynamic.Interface, error) {
	restConfig, err := c.ToRESTConfig()
	if err != nil {
		return nil, err
	}

	return dynamic.NewForConfig(restConfig)
}

func (c *clientFactory) KubernetesClientSet() (*kubernetes.Clientset, error) {
	restConfig, err := c.ToRESTConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(restConfig)
}

func (c *clientFactory) RESTClient() (*rest.RESTClient, error) {
	clientConfig, err := c.ToRESTConfig()
	if err != nil {
		return nil, err
	}
	return rest.RESTClientFor(clientConfig)
}

type rESTClientGetter interface {
	// ToRESTConfig returns restconfig
	ToRESTConfig() (*rest.Config, error)
	// ToDiscoveryClient returns discovery client
	ToDiscoveryClient() (discovery.CachedDiscoveryInterface, error)
	// ToRESTMapper returns a restmapper
	ToRESTMapper() (meta.RESTMapper, error)
	// ToRawKubeConfigLoader return kubeconfig loader as-is
	ToRawKubeConfigLoader() clientcmd.ClientConfig
}

type PartialFactory interface {
	rESTClientGetter

	// DynamicClient returns a dynamic client ready for use
	DynamicClient() (dynamic.Interface, error)

	// KubernetesClientSet gives you back an external clientset
	KubernetesClientSet() (*kubernetes.Clientset, error)

	// Returns a RESTClient for accessing Kubernetes resources or an error.
	RESTClient() (*rest.RESTClient, error)
}
