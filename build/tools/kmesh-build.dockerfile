# Dockerfile for building openEuler kmesh docker image.
# 
# Usage:
# docker build -f kmesh-build.dockerfile -t kmesh-build-x86:latest .
#

# base image
FROM openeuler/openeuler:23.09

# Setup Go
COPY --from=golang:1.22.1 /usr/local/go/ /usr/local/go/
RUN mkdir -p /go
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "${GOROOT}/bin:${GOPATH}/bin:${PATH}"

WORKDIR /prepare
COPY kmesh_compile_env_pre.sh ./
COPY go.mod ./

# install pkg dependencies 
# RUN yum install -y kmod util-linux
# install package in online-compile image
RUN yum install -y kmod \
    && yum install -y util-linux iptables

RUN go env -w GO111MODULE=on \
    && export GONOSUMDB=* \
    && go env -w GOPROXY=https://goproxy.cn,direct \
    && go mod download \
    && go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.32.0

RUN bash kmesh_compile_env_pre.sh

# container work directory
WORKDIR /kmesh
