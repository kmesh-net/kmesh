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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KmeshNode is the Schema for the kmeshnodes API
type KmeshNodeInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KmeshNodeInfoSpec   `json:"spec,omitempty"`
	Status KmeshNodeInfoStatus `json:"status,omitempty"`
}

type KmeshNodeInfoSpec struct {
	// The SPI is used to identify the version number of the current key.
	// The communication can be normal only when both communication parties
	// have spis and the spi keys are the same.
	SPI int `json:"spi"`
	// Addresses is used to store the internal ip address informatioon on the
	// host. The IP address information is used to generate the IPsec state
	// informatioon. IPsec uses this information to determine which network
	// adapter is used to encrypt and send data.
	Addresses []string `json:"addresses"`
	// bootid is used to generate the ipsec key. After the node is restarted,
	// the key needs to be updated.
	BootID string `json:"bootID"`
	// PodCIDRs used in IPsec checks the destination of the data to
	// determine which IPsec state is used for encryption.
	PodCIDRs []string `json:"podCIDRS"`
}

type KmeshNodeInfoStatus struct {
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KmeshNodeLists contains a list of KmeshNode
type KmeshNodeInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KmeshNodeInfo `json:"items"`
}
