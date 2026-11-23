#!/bin/bash

# Copyright The Kmesh Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

# Automation script to update Kmesh image in a kind cluster for testing.
# This script builds the local image, loads it into kind, and restarts the Kmesh pods.
# Usage: ./hack/kind-update-kmesh.sh [cluster_name] [image_name:tag]

CLUSTER_NAME=${1:-kind}
IMAGE_NAME=${2:-kmesh:latest}

echo ">>> Building Kmesh image: $IMAGE_NAME"

# Split IMAGE_NAME into HUB, TARGET, TAG to override Makefile variables
# e.g. "ghcr.io/kmesh-net/kmesh:v1.0" -> HUB="ghcr.io/kmesh-net", TARGET="kmesh", TAG="v1.0"
# e.g. "kmesh:latest" -> HUB="", TARGET="kmesh", TAG="latest"

IMAGE_PART="${IMAGE_NAME%%:*}"
TAG="${IMAGE_NAME##*:}"
if [ "$TAG" == "$IMAGE_PART" ]; then
    TAG="latest"
fi

if [[ "$IMAGE_PART" == *"/"* ]]; then
    HUB="${IMAGE_PART%/*}"
    TARGET="${IMAGE_PART##*/}"
else
    HUB=""
    TARGET="$IMAGE_PART"
fi

# The Makefile's docker target enforces HUB is non-empty.
# If no hub is provided, we use a placeholder and then tag correctly.
if [ -z "$HUB" ]; then
    DUMMY_HUB="local"
    make docker HUB="$DUMMY_HUB" TARGET="$TARGET" TAG="$TAG"
    echo ">>> Tagging image as $IMAGE_NAME..."
    docker tag "$DUMMY_HUB/$TARGET:$TAG" "$IMAGE_NAME"
    # Clean up the dummy tag
    docker rmi "$DUMMY_HUB/$TARGET:$TAG"
else
    make docker HUB="$HUB" TARGET="$TARGET" TAG="$TAG"
fi

echo ">>> Loading image $IMAGE_NAME into kind cluster $CLUSTER_NAME..."
kind load docker-image "$IMAGE_NAME" --name "$CLUSTER_NAME"

echo ">>> Restarting Kmesh daemonset..."
kubectl rollout restart daemonset kmesh -n kmesh-system

echo ">>> Waiting for Kmesh pods to be ready..."
kubectl rollout status daemonset kmesh -n kmesh-system

echo ">>> Kmesh update complete!"
