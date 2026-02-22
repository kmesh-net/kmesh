package k8s

import (
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClient 创建 Kubernetes 客户端。
// 若 KUBECONFIG 环境变量已设置则使用该文件，否则使用集群内配置（InClusterConfig）。
func NewClient(kubeconfigPath string) (kubernetes.Interface, error) {
	var config *rest.Config
	var err error

	if kubeconfigPath != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	} else if path := os.Getenv("KUBECONFIG"); path != "" {
		config, err = clientcmd.BuildConfigFromFlags("", path)
	} else {
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}
