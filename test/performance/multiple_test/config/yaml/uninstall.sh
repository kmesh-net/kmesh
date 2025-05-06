#!/bin/bash
kubectl delete -f cilium_policy.yaml
kubectl delete -f deployment.yaml
kubectl delete -f fortio-server.yaml
kubectl delete -f fortio-client.yaml
kubectl delete -f service.yaml
kubectl delete -f namespace.yaml
