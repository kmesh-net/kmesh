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
package kube

import (
	"os"
	"sync"

	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
)

var informerManager *InformerManager
var once sync.Once

type InformerManager struct {
	client  kubernetes.Interface
	mutex   sync.Mutex
	factory informers.SharedInformerFactory
}

func NewInformerManager(client kubernetes.Interface) *InformerManager {
	return &InformerManager{
		client: client,
	}
}

func getInformerFactory() informers.SharedInformerFactory {
	informerManager.mutex.Lock()
	defer informerManager.mutex.Unlock()

	if informerManager.factory == nil {
		nodeName := os.Getenv("NODE_NAME")
		informerManager.factory = informers.NewSharedInformerFactoryWithOptions(informerManager.client, 0,
			informers.WithTweakListOptions(func(options *metav1.ListOptions) {
				options.FieldSelector = fmt.Sprintf("spec.nodeName=%s", nodeName)
			}))
	}

	return informerManager.factory
}

func stopInformerFactory() {
	informerManager.mutex.Lock()
	defer informerManager.mutex.Unlock()

	if informerManager.factory != nil {
		informerManager.factory.Shutdown()
		informerManager.factory.WaitForCacheSync(make(chan struct{}))
		informerManager.factory = nil
		once = sync.Once{}
	}
}

func GetInformerFactory(client kubernetes.Interface) informers.SharedInformerFactory {
	once.Do(func() {
		informerManager = NewInformerManager(client)
	})

	return getInformerFactory()
}

func StopInformerFactory() {
	if informerManager != nil {
		stopInformerFactory()
	}
}
