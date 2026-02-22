package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"kmesh.net/kmesh-dashboard/backend/internal/auth"
	"kmesh.net/kmesh-dashboard/backend/internal/handler"
	"kmesh.net/kmesh-dashboard/backend/internal/k8s"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	"k8s.io/client-go/dynamic"
)

func main() {
	auth.InitStaticUsers()
	modelPath := os.Getenv("AUTH_MODEL")
	policyPath := os.Getenv("AUTH_POLICY")
	if modelPath == "" {
		modelPath = filepath.Join("internal", "auth", "model.conf")
	}
	if policyPath == "" {
		policyPath = filepath.Join("internal", "auth", "policy.csv")
	}
	if _, err := auth.InitEnforcer(modelPath, policyPath); err != nil {
		log.Fatalf("failed to init casbin enforcer: %v", err)
	}

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
	var h http.Handler = auth.AuthMiddleware(mux)

	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	log.Printf("Kmesh Dashboard backend listening on %s", addr)
	if err := http.ListenAndServe(addr, handler.CORS(h)); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
