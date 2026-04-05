#!/bin/bash
# Reproducer for Issue #1388: Routing Fails After Pod Multiple Restarts

set -e

echo "Testing Kmesh routing race conditions with rapid pod restarts..."

# Check if required pods are present
NETUTILS_POD=$(kubectl get pod -n default | grep netutils | awk '{print $1}')
FORTIO_POD=$(kubectl get pod -n default | grep fortio | awk 'NR==1{print $1}')

if [ -z "$NETUTILS_POD" ] || [ -z "$FORTIO_POD" ]; then
    echo "Warning: netutils or fortio pods not found in the 'default' namespace."
    echo "Please ensure you have applied the Kmesh routing example:"
    echo "kubectl apply -f https://raw.githubusercontent.com/kmesh-net/kmesh/main/docs/example/routing-ads.yaml"
    exit 1
fi

echo "Environment ready. Starting the rapid restart test."

for i in {1..3}; do
    echo "Attempt $i: Rapidly deleting all pods..."
    kubectl delete pods --all -n default
    
    echo "Waiting for pods to be recreated and ready..."
    kubectl wait -n default --for=condition=ready pod --all --timeout=60s || {
        echo "Timeout waiting for pods to become ready."
        kubectl get pods -n default
        exit 1
    }

    # Give Kmesh a brief moment to sync (as realistically happens in CI)
    sleep 2

    # Get the new netutils pod
    NEW_NETUTILS_POD=$(kubectl get pod -n default | grep netutils | awk '{print $1}')
    
    echo "Testing routing from $NEW_NETUTILS_POD..."
    CURL_OUT=$(kubectl exec -it "$NEW_NETUTILS_POD" -n default -- curl -v 10.96.60.149:80 2>&1 | grep "Server:" || true)
    
    if [[ -z "$CURL_OUT" ]]; then
        echo "❌ Routing failed on attempt $i! Endpoint not found or connection refused."
        echo "Check tracelog with: bpftool prog tracelog"
        exit 1
    fi
    
    echo "✅ Routing successful: $CURL_OUT"
done

echo "🎉 All restart loops completed successfully. The issue is not reproducing!"
