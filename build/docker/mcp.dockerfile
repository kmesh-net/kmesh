# Copyright The Kmesh Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Dockerfile for the Kmesh MCP server image.
#
# Usage:
#   make mcp-image
#   docker run -v ~/.kube/config:/kubeconfig -e KUBECONFIG=/kubeconfig kmesh-mcp:latest
#
# To use the SSE transport instead of stdio, append it to the run command:
#   docker run ... kmesh-mcp:latest --transport sse

FROM golang:1.25.5 AS builder
WORKDIR /kmesh
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /kmeshctl ./ctl

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /kmeshctl /kmeshctl
EXPOSE 8080
ENTRYPOINT ["/kmeshctl", "mcp", "serve"]
