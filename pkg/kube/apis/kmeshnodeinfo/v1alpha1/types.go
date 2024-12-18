package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
	Name string `json:"name"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=15
	Spi    int8     `json:"spi"`
	NicIPs []string `json:"nicIP"`
	BootID string   `json:"bootid"`
	Cirds  []string `json:"cirds"`
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
