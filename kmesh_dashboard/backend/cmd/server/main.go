package main

import (
	"log"
	"net/http"
	"os"

	"kmesh.net/kmesh-dashboard/backend/internal/handler"
	"kmesh.net/kmesh-dashboard/backend/internal/k8s"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	"k8s.io/client-go/dynamic"
)

func main() {
	kubeconfig := os.Getenv("KUBECONFIG")
	config, err := k8s.GetConfig(kubeconfig)
	if err != nil {
		log.Fatalf("failed to get k8s config: %v", err)
	}
	clientset, err := k8s.NewClient(config)
	if err != nil {
		log.Fatalf("failed to create k8s client: %v", err)
	}
	gwClient, err := gatewayapiclient.NewForConfig(config)
	if err != nil {
		log.Fatalf("failed to create gateway-api client: %v", err)
	}
	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		log.Fatalf("failed to create dynamic client: %v", err)
	}

	mux := http.NewServeMux()
	handler.Register(mux, clientset, gwClient, dyn)

	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	log.Printf("Kmesh Dashboard backend listening on %s", addr)
	if err := http.ListenAndServe(addr, handler.CORS(mux)); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
