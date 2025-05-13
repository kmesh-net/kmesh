#!/bin/bash
rm -rf ../../deploy/yaml/crd/kmesh.net_kmeshnodeinfoes.yaml
rm -rf apis/kmeshnodeinfo/v1alpha1/zz_generated.deepcopy.go
rm -rf nodeinfo/clientset
rm -rf nodeinfo/informers
rm -rf nodeinfo/listers
