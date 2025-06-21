#!/bin/bash
kubectl apply -f namespace.yaml
kubectl apply -f service.yaml
sh get_nginx_svc_address.sh
kubectl apply -f fortio-client.yaml
kubectl apply -f fortio-server.yaml
kubectl apply -f deployment.yaml
kubectl apply -f cilium_policy.yaml
