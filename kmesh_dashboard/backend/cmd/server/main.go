package main

import (
	"log"
	"net/http"
	"os"

	"kmesh.net/kmesh-dashboard/backend/internal/handler"
	"kmesh.net/kmesh-dashboard/backend/internal/k8s"
)

func main() {
	kubeconfig := os.Getenv("KUBECONFIG")
	clientset, err := k8s.NewClient(kubeconfig)
	if err != nil {
		log.Fatalf("failed to create k8s client: %v", err)
	}

	mux := http.NewServeMux()
	handler.Register(mux, clientset)

	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	log.Printf("Kmesh Dashboard backend listening on %s", addr)
	if err := http.ListenAndServe(addr, handler.CORS(mux)); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
